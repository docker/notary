<!--[metadata]>
+++
title = "Getting started with Notary"
description = "Performing basic operation to use Notary in tandem with Docker Content Trust."
keywords = ["docker, Notary, notary-client, docker content trust, content trust"]
[menu.main]
parent="mn_notary"
weight=1
+++
<![end-metadata]-->

# Getting started with Docker Notary

This document describes basic use of the Notary CLI as a tool supporting Docker
Content Trust. For more advanced use cases, you must [run your own Notary
service](running_a_service.md) and should read the [use the Notary client for
advanced users](advanced_usage.md) documentation.

## What is Notary

Notary is a tool for publishing and managing trusted collections of content.
Publishers can digitally sign collections and consumers can verify integrity
and origin of content. This ability is built on a straightforward key management
and signing interface to create signed collections and configure trusted publishers.

With Notary anyone can provide trust over arbitrary collections of data. Using
<a href="https://www.theupdateframework.com/" target="_blank">The Update Framework (TUF)</a>
as the underlying security framework, Notary takes care of the operations necessary
to create, manage and distribute the metadata necessary to ensure the integrity and
freshness of your content.

## Install Notary

You can download precompiled notary binary for 64 bit Linux or Mac OS X from the
Notary repository's
<a href="https://github.com/docker/notary/releases" target="_blank">releases page on
GitHub</a>. Windows is not officially
supported, but if you are a developer and Windows user, we would appreciate any
insight you can provide regarding issues.

## Delete a tag

Notary generates and stores signing keys on the host it's running on. This means
that the Docker Hub cannot delete tags from the trust data, they must be deleted
using the Notary client. You can do this with the `notary remove` command.
Again, you must direct it to speak to the correct Notary server (N.B. neither
you nor the author has permissions to delete tags from the official alpine
repository, the output below is for demonstration only):

```
$ notary -s https://notary.docker.io -d ~/.docker/trust remove docker.io/library/alpine 2.6
Removal of 2.6 from docker.io/library/alpine staged for next publish.
```

In the preceding example, the output message indicates that only the removal was
staged. When performing any write operations they are staged into a change list.
This list is applied to the latest version of the trust repository the next time
a `notary publish` is run for that repository.

You can see a pending change by running `notary status` for the modified
repository. The `status` subcommand is an offline operation and as such, does
not require the `-s` flag, however it will silently ignore the flag if provided.
Failing to provide the correct value for the `-d` flag may show the wrong
(probably empty) change list:

```
$ notary -d ~/.docker/trust status docker.io/library/alpine
Unpublished changes for docker.io/library/alpine:

\#  ACTION    SCOPE     TYPE        PATH
\-  ------    -----     ----        ----
0  delete    targets   target      2.6
$ notary -s https://notary.docker.io -d ~/.docker/trust  publish docker.io/library/alpine
```

## Managing the status changelist

Note that each row in the status has a number associated with it, found in the first
column. This number can be used to remove individual changes from the changelist if
they are no longer desired. This is done using the `reset` command:

```
$ notary -d ~/.docker/trust status docker.io/library/alpine 
Unpublished changes for docker.io/library/alpine:

\#  ACTION    SCOPE     TYPE        PATH
\-  ------    -----     ----        ----
0  delete    targets   target      2.6
1  create    targets   target      3.0

$ notary -d ~/.docker/trust reset docker.io/library/alpine -n 0
$ notary -d ~/.docker/trust status docker.io/library/alpine
Unpublished changes for docker.io/library/alpine:

\#  ACTION    SCOPE     TYPE        PATH
\-  ------    -----     ----        ----
0  create    targets   target      3.0
```

Pay close attention to how the indices are updated as changes are removed. You may
pass multiple `-n` flags with multiple indices in a single invocation of the
`reset` subcommand and they will all be handled correctly within that invocation. Between
invocations however, you should list the changes again to check which indices you want
to remove.

It is also possible to completely clear all pending changes by passing the `--all` flag
to the `reset` subcommand. This deletes all pending changes for the specified GUN.

## Configure the client

It is verbose and tedious to always have to provide the `-s` and `-d` flags
manually to most commands. A simple way to create preconfigured versions of the
Notary command is via aliases. Add the following to your `.bashrc` or
equivalent:

```
alias dockernotary="notary -s https://notary.docker.io -d ~/.docker/trust"
```

More advanced methods of configuration, and additional options, can be found in
the [configuration doc](reference/index.md) and by running `notary --help`.
