# Docker file for development image for greggd
#
# Builds image with all needed dependecies
#

FROM centos:8.3.2011

LABEL name="greggd-devel" \
      version="centos8.3-297"

RUN dnf install --enablerepo=powertools -y \
  @development git golang kernel-devel bcc-devel rpm-build make; \
  yum clean all

CMD ["/bin/bash"]
