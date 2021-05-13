# Docker file for development image for greggd
#
# Builds image with all needed dependecies
#

FROM registry.access.redhat.com/ubi8/ubi:8.3-297

LABEL name="greggd-devel" \
      version="rhel8.3-297"

RUN yum install -y @development git golang kernel-devel bcc-devel; yum clean all
RUN curl -LO https://github.com/goreleaser/nfpm/releases/download/v2.5.1/nfpm_amd64.rpm . && rpm -i nfpm_amd64.rpm && rm nfpm_amd64.rpm

CMD ["/bin/bash"]
