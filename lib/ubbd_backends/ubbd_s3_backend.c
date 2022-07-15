#define _GNU_SOURCE
#include "ubbd_uio.h"
#include "ubbd_backend.h"
#include "ubbd_queue.h"

#include <stddef.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "libs3.h"

static S3Protocol s3_protocal = S3ProtocolHTTP;
static S3UriStyle s3_uri_style = S3UriStylePath;
static int retry_count = 5;
static const char *s3_region = NULL;
static uint32_t s3_block_size;


// Environment variables, saved as globals ----------------------------------

static char *s3_accessid;
static char *s3_accesskey;
static char *s3_volume_name;
static char *s3_bucket_name;


// Request results, saved as globals -----------------------------------------

static int s3_status = 0;
static char err_details[4096] = { 0 };


// Other globals -------------------------------------------------------------

extern int s3_port;
static void S3_init(struct ubbd_s3_backend *s3_b)
{
	S3Status status;
	s3_port = s3_b->port;
	s3_accessid = s3_b->accessid;
	s3_accesskey = s3_b->accesskey;
	s3_volume_name = s3_b->volume_name;
	s3_block_size = s3_b->block_size;
	s3_bucket_name = s3_b->bucket_name;

	if ((status = S3_initialize("s3", S3_INIT_ALL, s3_b->hostname))
		!= S3StatusOK) {
		ubbd_info("Failed to initialize libs3: %s\n",
		S3_get_status_name(status));
		exit(-1);
	}
}

static S3Status rsp_prop_cb(const S3ResponseProperties *properties,
			void *cb_data)
{
	(void) cb_data;

	return S3StatusOK;
}


// response complete callback ------------------------------------------------

// This callback does the same thing for every request type: saves the status
// and error stuff in global variables
static void rsp_comp_cb(S3Status status,
			 const S3ErrorDetails *error,
			 void *cb_data)
{
	(void) cb_data;

	s3_status = status;
	// Compose the error details message now, although we might not use it.
	// Can't just save a pointer to [error] since it's not guaranteed to last
	// beyond this callback
	int len = 0;
	if (error && error->message) {
		len += snprintf(&(err_details[len]), sizeof(err_details) - len,
				        "  Message: %s\n", error->message);
	}
	if (error && error->resource) {
		len += snprintf(&(err_details[len]), sizeof(err_details) - len,
				        "  Resource: %s\n", error->resource);
	}
	if (error && error->furtherDetails) {
		len += snprintf(&(err_details[len]), sizeof(err_details) - len,
				        "  Further Details: %s\n", error->furtherDetails);
	}
	if (error && error->extraDetailsCount) {
		len += snprintf(&(err_details[len]), sizeof(err_details) - len,
				        "%s", "  Extra Details:\n");
		int i;
		for (i = 0; i < error->extraDetailsCount; i++) {
			len += snprintf(&(err_details[len]),
				            sizeof(err_details) - len, "    %s: %s\n",
				            error->extraDetails[i].name,
				            error->extraDetails[i].value);
		}
	}
}


static int should_retry()
{
	if (retry_count--) {
		static int retry_interval = 1;
		sleep(retry_interval);
		// Next sleep 1 second longer
		retry_interval++;
		return 1;
	}

	return 0;
}

static void printError()
{
	if (s3_status < S3StatusErrorAccessDenied) {
		ubbd_info("\nERROR: %s\n", S3_get_status_name(s3_status));
	}
	else {
		ubbd_info("\nERROR: %s\n", S3_get_status_name(s3_status));
		ubbd_info("%s\n", err_details);
	}
}

enum io_ctx_type {
	IO_CTX_TYPE_IOV,
	IO_CTX_TYPE_BUFF,
};

struct obj_io_ctx {
	enum io_ctx_type type;
	union {
		struct {
			struct iovec *iov;
			int iov_cnt;
		} iovec;
		struct {
			void *buff;
		} buffer;
	};
	uint32_t off;
	uint32_t len;
	uint32_t done;
};

static size_t
buf_to_iovec(const void *buf, size_t size, struct iovec *iov, size_t iovcnt, size_t offset)
{
	size_t i, len, done = 0;

	for (i = 0; i < iovcnt; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}

		if (iov[i].iov_base == NULL) {
			continue;
		}

		if (done >= size) {
			break;
		}

		len = MIN(size - done, iov[i].iov_len - offset);
		memcpy(iov[i].iov_base + offset, buf, len);
		buf += len;
		done += len;
		offset = 0;
	}

	return done;
}

static size_t
iovset(struct iovec *iov, size_t iovcnt, int byte, size_t size, size_t offset)
{
	size_t i, len, done = 0;

	for (i = 0; i < iovcnt; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}

		if (iov[i].iov_base == NULL) {
			continue;
		}

		if (done >= size) {
			break;
		}

		len = MIN(size - done, iov[i].iov_len - offset);
		memset(iov[i].iov_base + offset, byte, len);
		done += len;
		offset = 0;
	}

	return done;
}

static S3Status get_obj_data_cb(int buffer_size, const char *buffer,
				                      void *cb_data)
{
	struct obj_io_ctx *ctx = (struct obj_io_ctx *) cb_data;

	if (ctx->type == IO_CTX_TYPE_IOV) {
		ubbd_dbg("get object: iov: off: %u, len: %u, done: %u\n", ctx->off, buffer_size, ctx->done);
		buf_to_iovec(buffer, buffer_size, ctx->iovec.iov, ctx->iovec.iov_cnt, ctx->off + ctx->done);
	} else {
		ubbd_dbg("get object: buffer: off: %u, len: %u, done: %u\n", ctx->off, buffer_size, ctx->done);
		memcpy(ctx->buffer.buff + ctx->off + ctx->done, buffer, buffer_size);
	}

	ctx->done += buffer_size;

	return S3StatusOK;
}

static size_t
iovec_flatten(struct iovec *iov, size_t iovcnt, void *buf, size_t size, size_t offset)
{
	size_t i, len, done = 0;

	for (i = 0; i < iovcnt; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}

		if (iov[i].iov_base == NULL) {
			continue;
		}

		if (done >= size) {
			break;
		}

		len = MIN(size - done, iov[i].iov_len - offset);
		memcpy(buf, iov[i].iov_base + offset, len);
		buf += len;
		done += len;
		offset = 0;
	}

	return done;
}

static int put_obj_data_cb(int buffer_size, char *buffer,
				                 void *cb_data)
{
	struct obj_io_ctx *ctx = (struct obj_io_ctx *)cb_data;

	if (ctx->type == IO_CTX_TYPE_IOV) {
		ubbd_dbg("put object: iov: off: %u, len: %u, done: %u\n", ctx->off, buffer_size, ctx->done);
		iovec_flatten(ctx->iovec.iov, ctx->iovec.iov_cnt, buffer, buffer_size, ctx->off + ctx->done);
	} else {
		ubbd_dbg("put object: buffer: off: %u, len: %u, done: %u\n", ctx->off, buffer_size, ctx->done);
		memcpy(buffer, ctx->buffer.buff + ctx->off + ctx->done, buffer_size);
	}

	ctx->done += buffer_size;

	return buffer_size;
}


static int read_object(char *oid, uint64_t off, uint64_t len, struct obj_io_ctx *ctx)
{
	int64_t ifModifiedSince = -1, ifNotModifiedSince = -1;
	const char *ifMatch = 0, *ifNotMatch = 0;

	ubbd_dbg("read_object: %s, off: %lu, len: %lu\n", oid, off, len);

	S3BucketContext bucketContext =
	{
		0,
		s3_bucket_name,
		s3_protocal,
		s3_uri_style,
		s3_accessid,
		s3_accesskey,
		0,
		s3_region
	};

	S3GetConditions getConditions =
	{
		ifModifiedSince,
		ifNotModifiedSince,
		ifMatch,
		ifNotMatch
	};

	S3GetObjectHandler getObjectHandler =
	{
		{ &rsp_prop_cb, &rsp_comp_cb },
		&get_obj_data_cb
	};

	do {
		S3_get_object(&bucketContext, oid, &getConditions, off,
				      len, 0, 0, &getObjectHandler, ctx);
	} while (S3_status_is_retryable(s3_status) && should_retry());

	if (s3_status == S3StatusErrorNoSuchKey) {
		if (ctx->type == IO_CTX_TYPE_IOV) {
			iovset(ctx->iovec.iov, ctx->iovec.iov_cnt, 0, ctx->len, ctx->off);
		} else {
			memset(ctx->buffer.buff + ctx->off, 0, ctx->len);
		}
		s3_status = S3StatusOK;
	}

	if (s3_status != S3StatusOK) {
		printError();
	}

	return s3_status;
}

typedef int (obj_func_t)(char *oid, uint64_t off, uint64_t len, struct obj_io_ctx *ctx);

static int write_object(char *oid, uint64_t off, uint64_t len, struct obj_io_ctx *ctx)
{
	const char *cacheControl = 0, *contentType = 0, *md5 = 0;
	const char *contentDispositionFilename = 0, *contentEncoding = 0;
	int64_t expires = -1;
	S3CannedAcl cannedAcl = S3CannedAclPrivate;
	int metaPropertiesCount = 0;
	S3NameValue metaProperties[S3_MAX_METADATA_COUNT];
	char useServerSideEncryption = 0;
	struct obj_io_ctx internal_ctx;
	struct obj_io_ctx *write_ctx;
	void *obj_buf = NULL;

	ubbd_dbg("write_object: %s, off: %lu, len: %lu\n", oid, off, len);

	if (off || len != s3_block_size) {

		obj_buf = calloc(1, s3_block_size);
		if (!obj_buf) {
			return -ENOMEM;
		}

		internal_ctx.type = IO_CTX_TYPE_BUFF;
		internal_ctx.buffer.buff = obj_buf;

		internal_ctx.off = 0;
		internal_ctx.len = s3_block_size;
		internal_ctx.done = 0;

		read_object(oid, 0, s3_block_size, &internal_ctx);

		iovec_flatten(ctx->iovec.iov, ctx->iovec.iov_cnt, obj_buf + off, len, ctx->off);

		write_ctx = &internal_ctx;
		write_ctx->done = 0;
	} else {
		write_ctx = ctx;
	}

	S3BucketContext bucketContext =
	{
		0,
		s3_bucket_name,
		s3_protocal,
		s3_uri_style,
		s3_accessid,
		s3_accesskey,
		0,
		s3_region
	};

	S3PutProperties putProperties =
	{
		contentType,
		md5,
		cacheControl,
		contentDispositionFilename,
		contentEncoding,
		expires,
		cannedAcl,
		metaPropertiesCount,
		metaProperties,
		useServerSideEncryption
	};

	S3PutObjectHandler putObjectHandler =
	{
		{ &rsp_prop_cb, &rsp_comp_cb },
		&put_obj_data_cb
	};

	do {
		S3_put_object(&bucketContext, oid, s3_block_size, &putProperties, 0,
				  0, &putObjectHandler, write_ctx);
	} while (S3_status_is_retryable(s3_status) && should_retry());


	if (s3_status != S3StatusOK) {
		printError();
	}

	if (obj_buf)
		free(obj_buf);

	return s3_status;
}

#define S3_BACKEND(ubbd_b) ((struct ubbd_s3_backend *)container_of(ubbd_b, struct ubbd_s3_backend, ubbd_b))

static int s3_backend_open(struct ubbd_backend *ubbd_b)
{
	struct ubbd_s3_backend *s3_b = S3_BACKEND(ubbd_b);

	S3_init(s3_b);

	return 0;
}

static void s3_backend_close(struct ubbd_backend *ubbd_b)
{
	S3_deinitialize();

	return;
}

static void s3_backend_release(struct ubbd_backend *ubbd_b)
{
	struct ubbd_s3_backend *s3_backend = S3_BACKEND(ubbd_b);

	if (s3_backend)
		free(s3_backend);
}

enum submit_io_type {
	SUBMIT_IO_TYPE_WRITE,
	SUBMIT_IO_TYPE_READ,
};

static int submit_io(struct ubbd_backend_io *io, obj_func_t obj_func)
{
	struct obj_io_ctx ctx;
	char *oid;
	int start_obj = io->offset / s3_block_size;
	int end_obj = round_up((io->offset + io->len), s3_block_size) / s3_block_size;
	int offset = io->offset % s3_block_size;
	uint64_t remain = io->len;
	uint32_t done = 0;
	int ret = 0;
	int i;

	ctx.type = IO_CTX_TYPE_IOV;
	ctx.iovec.iov = io->iov;
	ctx.iovec.iov_cnt = io->iov_cnt;

	for (i = start_obj; i < end_obj; i++) {
		asprintf(&oid, "%s_%d", s3_volume_name, i);
		ctx.off = done;
		ctx.len = MIN(s3_block_size - offset, remain);
		ctx.done = 0;
		ret = obj_func(oid, offset, ctx.len, &ctx);
		free(oid);

		done += ctx.len;
		remain -= ctx.len;
		offset = 0;

		if (ret)
			break;
	}

	ubbd_backend_io_finish(io, ret);

	return ret;
}


static int s3_backend_writev(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_dbg("write off: %lu, len: %u\n", io->offset, io->len);

	return submit_io(io, write_object);
}

static int s3_backend_readv(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_dbg("read off: %lu, len: %u\n", io->offset, io->len);

	return submit_io(io, read_object);
}

static int s3_backend_flush(struct ubbd_backend *ubbd_b, struct ubbd_backend_io *io)
{
	ubbd_backend_io_finish(io, 0);

	return 0;
}

struct ubbd_backend_ops s3_backend_ops = {
	.open = s3_backend_open,
	.close = s3_backend_close,
	.release = s3_backend_release,
	.writev = s3_backend_writev,
	.readv = s3_backend_readv,
	.flush = s3_backend_flush,
};
