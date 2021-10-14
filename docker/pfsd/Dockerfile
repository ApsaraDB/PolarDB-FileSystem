# Copyright (c) 2017-2021, Alibaba Group Holding Limited
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG IMAGE
FROM $IMAGE

ARG RPM
ARG VERSION

LABEL dev_version="$VERSION"

USER root

COPY pfsd_supervisor.py /docker_script/
COPY log.conf  /docker_script/
COPY libzlog.so* /usr/lib64/
COPY pre_stop_pfsd.sh /usr/local/polarstore/pfsd/bin/ 
COPY $RPM /opt/

ENV PYTHONPATH /docker_script
ENV RPM_ENV $RPM

ENTRYPOINT ["python", "/docker_script/pfsd_supervisor.py"]
CMD ["-f", "-c", "/usr/local/polarstore/pfsd/conf/pfsd_logger.conf"]

RUN /usr/bin/yum makecache && \
    yum install -y python27 &&\
    ln -s /usr/bin/python2.7 /usr/bin/python && \
    /usr/bin/yum install -y libaio && \
    rpm -ivh /opt/$RPM_ENV && \
    chmod +x /usr/local/polarstore/pfsd/bin/start_pfsd.sh && \
    chmod +x /usr/local/polarstore/pfsd/bin/stop_pfsd.sh && \
    mkdir -p /dev/shm/pfsd && \
    chmod 777 /dev/shm/pfsd && \
    mkdir -p /var/log && \
    chmod 777 /var/log && \
    mkdir -p /var/run/pfsd && \
    chmod 777 /var/run/pfsd && \
    chmod 777 /docker_script && \
    /usr/bin/yum install -y gdb

