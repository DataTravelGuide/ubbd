#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_backend.h"
#include <libssh/libssh.h>

#define SSH_DEV(ubbd_b) ((struct ubbd_ssh_backend *)container_of(ubbd_b, struct ubbd_ssh_backend, ubbd_b))

static ssh_session connect_ssh(const char *host, const char *user, int verbosity){
	ssh_session session;
	int auth=0;

	session=ssh_new();
	if (session == NULL) {
		goto out;
	}

	if (user != NULL){
		if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
			goto free;
		}
	}

	if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
		goto free;
	}

	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	if (ssh_connect(session)){
		ubbd_err("Connection failed : %s\n", ssh_get_error(session));
		goto free;
	}

	auth = ssh_userauth_publickey_auto(session, NULL, NULL);
	if (auth != SSH_AUTH_SUCCESS) {
		if(auth == SSH_AUTH_DENIED){
			ubbd_err("Authentication failed\n");
			goto disconnect;
		} else {
			ubbd_err("Error while authenticating : %s\n", ssh_get_error(session));
			goto disconnect;
		}
	}

	return session;

disconnect:
	ssh_disconnect(session);
free:
	ssh_free(session);
out:
	return NULL;
}

static int ssh_backend_open(struct ubbd_backend *ubbd_b)
{
	struct ubbd_ssh_backend *ssh_b = SSH_DEV(ubbd_b);
	struct ssh_session_struct *ssh_session;
	struct sftp_session_struct *sftp_session;
	int ret;

	ssh_session = connect_ssh(ssh_b->hostname, NULL, 0);
	if (!ssh_session) {
		ubbd_err("failed to open ssh session.\n");
		ret = -ECONNREFUSED;
		goto out;
	}

	sftp_session = sftp_new(ssh_session);
	if (!sftp_session) {
		ubbd_err("failed to new sftp sessionu\n");
		ret = -ENOMEM;
		goto disconnect;
	}

	ret = sftp_init(sftp_session);
	if (ret) {
		ubbd_err("error to init sftp: %s\n", ssh_get_error(ssh_session));
		goto free;
	}

	ssh_b->sftp_file = sftp_open(sftp_session, ssh_b->path, O_RDWR, 0);
	if (!ssh_b->sftp_file) {
		ubbd_err("failed to open remote file.\n");
		goto free;
	}

	return 0;
free:
	sftp_free(sftp_session);
disconnect:
	ssh_disconnect(ssh_session);
	ssh_free(ssh_session);
out:
	return ret;
}

static void ssh_backend_close(struct ubbd_backend *ubbd_b)
{
	struct ubbd_ssh_backend *ssh_b = SSH_DEV(ubbd_b);
	struct sftp_session_struct *sftp_session = ssh_b->sftp_file->sftp;
	struct ssh_session_struct *ssh_session = sftp_session->session;

	sftp_close(ssh_b->sftp_file);
	sftp_free(sftp_session);
	ssh_disconnect(ssh_session);
	ssh_free(ssh_session);
}

static void ssh_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_ssh_backend *ssh_b = SSH_DEV(ubbd_b);

	if (ssh_b)
		free(ssh_b);
}

static int ssh_backend_writev(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_backend *ubbd_b = ubbd_q->ubbd_b;
	struct ubbd_ssh_backend *ssh_b = SSH_DEV(ubbd_b);
	int ret;
	ssize_t count = 0;
	void *base;
	ssize_t len;
	int i;

	pthread_mutex_lock(&ssh_b->lock);
	sftp_seek(ssh_b->sftp_file, se->offset);

	for (i = 0; i < se->iov_cnt; i++) {
		base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		len = se->iov[i].iov_len;
		ret = sftp_write(ssh_b->sftp_file, base, len);
		if (ret < 0) {
			ubbd_err("error in sftp_write: %d\n", ret);
			pthread_mutex_unlock(&ssh_b->lock);
			goto out;
		}
		count += ret;
	}
	pthread_mutex_unlock(&ssh_b->lock);

	ubbd_queue_add_ce(ubbd_q, se->priv_data, (count == se->len? 0 : -5));

	return 0;
out:
	return ret;
}

static int ssh_backend_readv(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_backend *ubbd_b = ubbd_q->ubbd_b;
	struct ubbd_ssh_backend *ssh_b = SSH_DEV(ubbd_b);
	int ret;
	ssize_t count = 0;
	void *base;
	ssize_t len;
	int i;

	pthread_mutex_lock(&ssh_b->lock);
	sftp_seek(ssh_b->sftp_file, se->offset);

	for (i = 0; i < se->iov_cnt; i++) {
		base = (void*)ubbd_q->uio_info.map + (size_t)se->iov[i].iov_base;
		len = se->iov[i].iov_len;
		ret = sftp_read(ssh_b->sftp_file, base, len);
		if (ret < 0) {
			ubbd_err("error in sftp_write: %d\n", ret);
			pthread_mutex_unlock(&ssh_b->lock);
			goto out;
		}
		count += ret;
	}
	pthread_mutex_unlock(&ssh_b->lock);

	ubbd_queue_add_ce(ubbd_q, se->priv_data, (count == se->len? 0 : -5));

	return 0;
out:
	return ret;
}

static int ssh_backend_flush(struct ubbd_queue *ubbd_q, struct ubbd_se *se)
{
	struct ubbd_backend *ubbd_b = ubbd_q->ubbd_b;
	struct ubbd_ssh_backend *ssh_b = SSH_DEV(ubbd_b);
	int ret;

	ret = sftp_fsync(ssh_b->sftp_file);

	ubbd_queue_add_ce(ubbd_q, se->priv_data, ret);

	return 0;
}

struct ubbd_backend_ops ssh_backend_ops = {
	.open = ssh_backend_open,
	.close = ssh_backend_close,
	.release = ssh_backend_release,
	.writev = ssh_backend_writev,
	.readv = ssh_backend_readv,
	.flush = ssh_backend_flush,
};
