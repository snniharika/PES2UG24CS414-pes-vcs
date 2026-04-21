// commit.c — Commit creation and history traversal

#include "commit.h"
#include "index.h"
#include "tree.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out);

/* ---------------- PROVIDED ---------------- */

int commit_parse(const void *data, size_t len, Commit *commit_out) {
    const char *p = (const char *)data;
    const char *end = p + len;
    char line[1024];
    char hex[HASH_HEX_SIZE + 1];

    memset(commit_out, 0, sizeof(Commit));

    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        if (!nl) nl = end;

        size_t l = nl - p;
        if (l >= sizeof(line)) l = sizeof(line) - 1;

        memcpy(line, p, l);
        line[l] = '\0';

        if (l == 0) {
            p = (nl < end) ? nl + 1 : nl;

            size_t msg_len = end - p;
            if (msg_len >= sizeof(commit_out->message))
                msg_len = sizeof(commit_out->message) - 1;

            memcpy(commit_out->message, p, msg_len);
            commit_out->message[msg_len] = '\0';
            return 0;
        }

        if (strncmp(line, "tree ", 5) == 0) {
            if (hex_to_hash(line + 5, &commit_out->tree) != 0) return -1;
        }
        else if (strncmp(line, "parent ", 7) == 0) {
            if (hex_to_hash(line + 7, &commit_out->parent) != 0) return -1;
            commit_out->has_parent = 1;
        }
        else if (strncmp(line, "author ", 7) == 0) {
            char temp[256];
            snprintf(temp, sizeof(temp), "%s", line + 7);

            char *last_space = strrchr(temp, ' ');
            if (!last_space) return -1;

            commit_out->timestamp = strtoull(last_space + 1, NULL, 10);
            *last_space = '\0';

            snprintf(commit_out->author,
                     sizeof(commit_out->author),
                     "%s", temp);
        }

        p = (nl < end) ? nl + 1 : nl;
    }

    return -1;
}

int commit_serialize(const Commit *commit, void **data_out, size_t *len_out) {
    char tree_hex[HASH_HEX_SIZE + 1];
    char parent_hex[HASH_HEX_SIZE + 1];
    char buf[8192];

    hash_to_hex(&commit->tree, tree_hex);

    int n = 0;
    n += snprintf(buf + n, sizeof(buf) - n, "tree %s\n", tree_hex);

    if (commit->has_parent) {
        hash_to_hex(&commit->parent, parent_hex);
        n += snprintf(buf + n, sizeof(buf) - n, "parent %s\n", parent_hex);
    }

    n += snprintf(buf + n, sizeof(buf) - n,
                  "author %s %" PRIu64 "\n"
                  "committer %s %" PRIu64 "\n"
                  "\n"
                  "%s",
                  commit->author, commit->timestamp,
                  commit->author, commit->timestamp,
                  commit->message);

    *data_out = malloc(n + 1);
    if (!*data_out) return -1;

    memcpy(*data_out, buf, n + 1);
    *len_out = n;
    return 0;
}

int commit_walk(commit_walk_fn callback, void *ctx) {
    ObjectID id;
    if (head_read(&id) != 0) return -1;

    while (1) {
        ObjectType type;
        void *raw;
        size_t raw_len;

        if (object_read(&id, &type, &raw, &raw_len) != 0) return -1;

        Commit c;
        int rc = commit_parse(raw, raw_len, &c);
        free(raw);

        if (rc != 0) return -1;

        callback(&id, &c, ctx);

        if (!c.has_parent) break;
        id = c.parent;
    }

    return 0;
}

int head_read(ObjectID *id_out) {
    FILE *f = fopen(HEAD_FILE, "r");
    if (!f) return -1;

    char line[512];

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }

    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';

    char ref_path[512];

    if (strncmp(line, "ref: ", 5) == 0) {
        snprintf(ref_path, sizeof(ref_path), "%s/%s", PES_DIR, line + 5);

        f = fopen(ref_path, "r");
        if (!f) return -1;

        if (!fgets(line, sizeof(line), f)) {
            fclose(f);
            return -1;
        }

        fclose(f);
        line[strcspn(line, "\r\n")] = '\0';
    }

    return hex_to_hash(line, id_out);
}

int head_update(const ObjectID *new_commit) {
    FILE *f = fopen(HEAD_FILE, "r");
    if (!f) return -1;

    char line[512];

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }

    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';

    char target[512];

    if (strncmp(line, "ref: ", 5) == 0)
        snprintf(target, sizeof(target), "%s/%s", PES_DIR, line + 5);
    else
        snprintf(target, sizeof(target), "%s", HEAD_FILE);

    char tmp[520];
    snprintf(tmp, sizeof(tmp), "%s.tmp", target);

    f = fopen(tmp, "w");
    if (!f) return -1;

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(new_commit, hex);

    fprintf(f, "%s\n", hex);
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    return rename(tmp, target);
}

/* ---------------- TODO IMPLEMENTED ---------------- */

int commit_create(const char *message, ObjectID *commit_id_out) {
    Commit c;
    memset(&c, 0, sizeof(c));

    if (tree_from_index(&c.tree) != 0)
        return -1;

    if (head_read(&c.parent) == 0)
        c.has_parent = 1;
    else
        c.has_parent = 0;

    strncpy(c.author, pes_author(), sizeof(c.author) - 1);
    c.author[sizeof(c.author) - 1] = '\0';

    c.timestamp = (uint64_t)time(NULL);

    strncpy(c.message, message, sizeof(c.message) - 1);
    c.message[sizeof(c.message) - 1] = '\0';

    void *data;
    size_t len;

    if (commit_serialize(&c, &data, &len) != 0)
        return -1;

    if (object_write(OBJ_COMMIT, data, len, commit_id_out) != 0) {
        free(data);
        return -1;
    }

    free(data);

    if (head_update(commit_id_out) != 0)
        return -1;

    return 0;
}
