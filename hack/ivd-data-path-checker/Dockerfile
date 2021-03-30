FROM ubuntu:focal
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ADD /bin/linux/amd64/data-* /datamgr
RUN mkdir /vddkLibs
COPY /bin/linux/amd64/lib/vmware-vix-disklib/lib64/* /vddkLibs/
USER nobody:nogroup
ENTRYPOINT ["/datamgr"]
