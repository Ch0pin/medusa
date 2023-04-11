FROM python:3
RUN apt-get update && apt-get install -y android-tools-adb git
RUN git clone https://github.com/ch0pin/medusa
RUN pip install --upgrade pip
RUN cd /medusa && pip install -r requirements.txt --upgrade
CMD ["/bin/bash"]