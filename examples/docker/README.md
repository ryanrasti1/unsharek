# unsharek in a Docker image

A plain `Dockerfile` (alpine), with unsharek copied in. Docker is the outer jail: its namespaces
decide which files and network exist. unsharek is the inner one: its seccomp filter decides which
host kernel calls the program can make, a few, each argument pinned. They stack: inside the
container a program reaches the host kernel only through unsharek's calls.

```sh
examples/docker/context.sh target/docker-context        # the binary and the store paths it links
docker build -t unsharek-example -f examples/docker/Dockerfile target/docker-context
docker run --rm unsharek-example                         # the image's busybox, sandboxed
```

The image's own files are the sandbox's with `--mount DIR:map`: mapped in place, read-only, no
copy, and nothing added to the filter. That is the mount to use in a container almost always.

`--mount DIR:ro` and `DIR:rw` (experimental) serve a directory live, through the host's file
calls, under unsharek's Landlock ruleset. Docker's default seccomp profile allows Landlock
(Docker 29 here); a profile that hides it makes those mounts fail with an error that names
`--no-landlock`. That flag leaves the paths to the container's own mount namespace, which is what
it is for.

`--net host` makes the program's sockets the container's: what it can reach is the container's
network.

`cargo xtask test-docker` (`test.sh`) builds the image and runs each of these under Docker's
default profile; it is skipped without a daemon.
