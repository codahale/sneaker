# This project is not ready to use. Please come back later.

![ha ha the 90s](http://i.imgur.com/3HvHOnm.gif)

# secman

`secman` is a utility for storing sensitive information on AWS using S3
and the Key Management Service (KMS) to provide durability,
confidentiality, and integrity.

Secrets are stored on S3, encrypted with AES-GCM and single-use,
KMS-generated data keys.

## Installing

```shell
go get -d -u github.com/stripe/secman
cd $GOPATH/src/github.com/stripe/secman
make install
secman version
```

## Using

### Configuring Access to AWS

`secman` requires access to AWS APIs, which means it needs a set of AWS
credentials. It will look for the `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` environment variables, the default credentials
profile (e.g. `~/.aws/credentials`), and finally any instance profile
credentials for systems running on EC2 instances.

You should also specify which region you'll be operating in via the
`AWS_DEFAULT_REGION` environment variable.

In general, if the `aws` command works, `secman` should work as well.

### Setting Up The Environment

`secman` needs two things: the ID of a KMS key and the S3 path where
secrets will be stored.

You can create a KMS key via the AWS Console or using a recent version
of `aws`. When you've created the key, store its ID (a UUID) in the
`KMS_KEY_ID` environment variable.

As with the key, you can create an S3 bucket via the AWS Console or with
the `aws` command. You can either use a dedicated bucket or use a
directory in a common bucket, but we recommend you do two things:

1. Use a `Private` ACL. In addition to the cryptographic controls of
   `secman`, access control is critical in preventing security breaches.

2. Enable access logging, ideally to a tightly-controlled, secure
   bucket. While Amazon's CloudTrail provides audit logging for the vast
   majority of AWS services, it does not do so for S3 access.

Once you're done, set the `S3_PATH` environment variable to the location
where secrets should be stored (e.g. `s3://bucket1/secrets/`).

### Managing Secrets

#### Basic Operations

Once you've got `secman` configured, try listing all the secrets:

```shell
secman ls
```

This will print out a table of all uploaded secrets. If you haven't
uploaded anything yet, the table will be empty.

Let's create an example secret file and upload it:

```shell
echo "This is a secret!" > secret.txt
secman upload secret.txt /example/secret.txt
```

This will use KMS to generate a random, 256-bit data key, encrypt the
secret with AES-GCM, and upload the encrypted secret and an encrypted
copy of the data key to S3. Running `secman ls` should display a table
with the file in it.

If your file is so sensitive it shouldn't be stored on disk, using `-`
instead of a filename will make `secman` read the data from `STDIN`.

Finally, you can delete the file:

```shell
secman rm /example/secret.txt
```

#### Packing And Unpacking

To install a secret on a machine, you'll need to first create a package:

```shell
secman pack /example/* example.enc.tar
```

This will perform the following steps:

1. Download and decrypt all secrets matching the `/example/*` pattern.

2. Package all the decrypted secrets into a `TAR` file in memory.

3. Generate a new data key using KMS.

4. Use the data key to encrypt the `TAR` file with AES-GCM.

5. Package the encrypted `TAR` file and the encrypted data key in a
   `TAR` file and write it to `example-secrets.tar`.

(To simplify things, if you specify `-` as the output path,
`secman` will write the data to STDOUT.)

The result is safe to store and transmit -- only those with access to
the `Decrypt` operation of the KMS key being used will be able to
decrypt the data.

To unpackage the secrets, run the following:

```shell
secman unpack example.enc.tar example.sec.tar
```

This will perform the following steps:

1. Read `example.enc.tar`.

2. Extract the encrypted data key and encrypted `TAR` file.

3. Use KMS to decrypt the data key.

4. Decrypt the `TAR` file and write the result to `example.sec.tar`.

(To simplify things, if you specify `-` as the output path, `secman`
will write the data to STDOUT, allowing you to pipe the output directly
to `tar`.)

### Maintenance Operations

A common maintenance task is key rotate. To rotate the data keys used to
encrypt the secrets, run `secman rotate`. It will download and decrypt
each secret, generate a new data key, and upload a re-encrypted copy.

To rotate the KMS key used for each secret, simply specify a different
`KMS_KEY_ID` and run `secman rotate`.
