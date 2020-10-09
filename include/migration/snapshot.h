/*
 * QEMU snapshots
 *
 * Copyright (c) 2004-2008 Fabrice Bellard
 * Copyright (c) 2009-2015 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_MIGRATION_SNAPSHOT_H
#define QEMU_MIGRATION_SNAPSHOT_H

/**
 * save_snapshot: Save a snapshot.
 * @name: path to snapshot
 * @errp: pointer to error object
 * On success, return %true.
 * On failure, store an error through @errp and return %false.
 */
bool save_snapshot(const char *name, Error **errp);
/**
 * save_snapshot: Load a snapshot.
 * @name: path to snapshot
 * @errp: pointer to error object
 * On success, return %true.
 * On failure, store an error through @errp and return %false.
 */
bool load_snapshot(const char *name, Error **errp);

#endif
