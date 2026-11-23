# unsharek in an ordinary container image. Docker is the outer jail (its namespaces: the image's
# files, its network); unsharek is the inner one (its seccomp filter: a few host calls, each
# argument pinned), so a program in it reaches the host kernel through those calls only.
#
# The build context is examples/docker/context.sh's: the unsharek binary and the store paths it
# links (it is a Nix build), nothing else of the host's.
#
#   examples/docker/context.sh target/docker-context && docker build -t unsharek-example -f examples/docker/Dockerfile target/docker-context
#   docker run --rm unsharek-example
FROM alpine:3.21

COPY nix /nix
COPY unsharek /usr/local/bin/unsharek

# Something for the program to read.
RUN mkdir -p /data && echo "hello from the image" > /data/hello.txt

# The image's own busybox, in a sandbox: its files mapped in place (`map`: read-only, no copy, no
# host call added), the data too.
CMD ["unsharek", "--mode", "fork", "--mount", "/bin:map", "--mount", "/lib:map", "--mount", "/data:map", \
     "--", "/bin/busybox", "cat", "/data/hello.txt"]
