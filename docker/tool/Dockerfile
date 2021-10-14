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

COPY entry_oper.py /docker_script/
COPY pfsd_oper.py  /docker_script/
COPY log.conf  /docker_script/
COPY $RPM /opt/
COPY pre_stop_pfsd.sh /usr/local/polarstore/pfsd/bin/ 

ENV RPM_ENV $RPM
ENV PYTHONPATH /docker_script
ENTRYPOINT ["python2", "/docker_script/pfsd_oper.py"]

RUN touch /var/lib/yum && \
    touch /var/lib/rpm/* &&\
    yum install -y python27 && \
    ln -s /usr/bin/python2.7 /usr/bin/python && \
    yum install -y libaio && \
    rpm -ivh /opt/$RPM_ENV && \
    chmod -R +x /docker_script && \
    yum install -y gdb

