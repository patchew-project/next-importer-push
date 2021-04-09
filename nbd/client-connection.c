/*
 * QEMU Block driver for  NBD
 *
 * Copyright (c) 2021 Virtuozzo International GmbH.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"

#include "block/nbd.h"

#include "qapi/qapi-visit-sockets.h"
#include "qapi/clone-visitor.h"

struct NBDClientConnection {
    /* Initialization constants */
    SocketAddress *saddr; /* address to connect to */

    /*
     * Result of last attempt. Valid in FAIL and SUCCESS states.
     * If you want to steal error, don't forget to set pointer to NULL.
     */
    QIOChannelSocket *sioc;
    Error *err;

    int refcnt; /* atomic access */

    QemuMutex mutex;
    /* All further fields are protected by mutex */
    bool running; /* thread is running now */
    Coroutine *wait_co; /* nbd_co_establish_connection() wait in yield() */
};

NBDClientConnection *nbd_client_connection_new(const SocketAddress *saddr)
{
    NBDClientConnection *conn = g_new(NBDClientConnection, 1);

    *conn = (NBDClientConnection) {
        .saddr = QAPI_CLONE(SocketAddress, saddr),
        .refcnt = 1,
    };

    qemu_mutex_init(&conn->mutex);

    return conn;
}

void nbd_client_connection_unref(NBDClientConnection *conn)
{
    if (qatomic_dec_fetch(&conn->refcnt) == 0) {
        if (conn->sioc) {
            qio_channel_close(QIO_CHANNEL(conn->sioc), NULL);
        }
        error_free(conn->err);
        qapi_free_SocketAddress(conn->saddr);
        g_free(conn);
    }
}

static void *connect_thread_func(void *opaque)
{
    NBDClientConnection *conn = opaque;
    int ret;

    conn->sioc = qio_channel_socket_new();

    error_free(conn->err);
    conn->err = NULL;
    ret = qio_channel_socket_connect_sync(conn->sioc, conn->saddr, &conn->err);
    if (ret < 0) {
        object_unref(OBJECT(conn->sioc));
        conn->sioc = NULL;
    }

    qemu_mutex_lock(&conn->mutex);

    assert(conn->running);
    conn->running = false;
    if (conn->wait_co) {
        aio_co_wake(conn->wait_co);
        conn->wait_co = NULL;
    }

    qemu_mutex_unlock(&conn->mutex);

    nbd_client_connection_unref(conn);

    return NULL;
}

/*
 * Get a new connection in context of @conn:
 *   if thread is running, wait for completion
 *   if thread is already succeeded in background, and user didn't get the
 *     result, just return it now
 *   otherwise if thread is not running, start a thread and wait for completion
 */
QIOChannelSocket *coroutine_fn
nbd_co_establish_connection(NBDClientConnection *conn, Error **errp)
{
    QIOChannelSocket *sioc = NULL;
    QemuThread thread;

    qemu_mutex_lock(&conn->mutex);

    /*
     * Don't call nbd_co_establish_connection() in several coroutines in
     * parallel. Only one call at once is supported.
     */
    assert(!conn->wait_co);

    if (!conn->running) {
        if (conn->sioc) {
            /* Previous attempt finally succeeded in background */
            sioc = g_steal_pointer(&conn->sioc);
            qemu_mutex_unlock(&conn->mutex);

            return sioc;
        }

        conn->running = true;
        error_free(conn->err);
        conn->err = NULL;
        qatomic_inc(&conn->refcnt); /* for thread */
        qemu_thread_create(&thread, "nbd-connect",
                           connect_thread_func, conn, QEMU_THREAD_DETACHED);
    }

    conn->wait_co = qemu_coroutine_self();

    qemu_mutex_unlock(&conn->mutex);

    /*
     * We are going to wait for connect-thread finish, but
     * nbd_co_establish_connection_cancel() can interrupt.
     */
    qemu_coroutine_yield();

    qemu_mutex_lock(&conn->mutex);

    if (conn->running) {
        /*
         * Obviously, drained section wants to start. Report the attempt as
         * failed. Still connect thread is executing in background, and its
         * result may be used for next connection attempt.
         */
        error_setg(errp, "Connection attempt cancelled by other operation");
    } else {
        error_propagate(errp, conn->err);
        conn->err = NULL;
        sioc = g_steal_pointer(&conn->sioc);
    }

    qemu_mutex_unlock(&conn->mutex);

    return sioc;
}

/*
 * nbd_co_establish_connection_cancel
 * Cancel nbd_co_establish_connection() asynchronously. Note, that it doesn't
 * stop the thread itself neither close the socket. It just safely wakes
 * nbd_co_establish_connection() sleeping in the yield().
 */
void coroutine_fn nbd_co_establish_connection_cancel(NBDClientConnection *conn)
{
    qemu_mutex_lock(&conn->mutex);

    if (conn->wait_co) {
        aio_co_wake(conn->wait_co);
        conn->wait_co = NULL;
    }

    qemu_mutex_unlock(&conn->mutex);
}
