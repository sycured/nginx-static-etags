Nginx Static Etags
------------------

## Configuration

Add `etags` to the relevant `location` blocks in your `nginx.conf` file:

    location / {
        ...
        etags on;
        etag_hash on|off;
        etag_hash_method md5|sha1;
        ...
    }
