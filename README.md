<img src="https://raw.githubusercontent.com/Ch0pin/medusa/master/libraries/logo.svg" width ="1835" height="508">

# Description

**MEDUSA** is an extensible, modular framework for automated dynamic runtime analysis of Android and iOS applications, built for penetration testers, mobile security researchers, and malware analysts. It serves as a centralized FRIDA script repository, allowing you to add or remove modules dynamically — combining hooks and behaviors into a single main script tailored to the needs of each pentest or malware analysis session. MEDUSA automates key tasks such as SSL-pinning bypasses, attack surface enumeration, network and WebView inspection, and proxy orchestration, while providing deep behavioral insight through API call tracing, memory inspection, cryptographic data extraction, and malware-specific monitoring (exfiltration, camera/mic abuse, SMS or call interception). With over 90 plug-and-play modules, MEDUSA makes large-scale instrumentation, triage, and behavioral investigation efficient, scalable, and reusable.

**System requirements:** 

- Linux or macOS (limited functionality available on Windows)
- Python 3
- Rooted device or emulator 
- adb
- FRIDA server (running on the mobile device)

# Installation

1.	Clone this repository.
2.	CD into the medusa directory.
3.	Install dependencies:

```sh
# using the system python3/pip
pip3 install -r requirements.txt

# or inside a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```
### Using Docker

A preconfigured Dockerfile is available in the medusa/ directory.

1.	Build the image: `docker build -t medusa:latest ./`

2.	Run the container: `docker run --name medusa --net=host --rm -it medusa:latest`

3.	Enable ADB over TCP/IP on your physical device or emulator: `adb tcpip 5555`

4.	Connect to the device from inside the container: `root@docker# adb connect <device_ip>:5555`

## Known installation issues

### macOS 

During installation on macOS, you might encounter the following issue:

>Readline features including tab completion have been disabled because
no supported version of readline was found. To resolve this, install
pyreadline3 on Windows or gnureadline on Linux/Mac.

To resolve, install the gnureadline package for Python:

```
pip install gnureadline
```

For Python 3.12, use the following command to install gnureadline from a specific commit:

```
pip install git+https://github.com/ludwigschwardt/python-gnureadline.git@8474e5583d4473f96b42745393c3492e2cb49224
```


# Usage

### Check our [wiki page](https://github.com/Ch0pin/medusa/wiki) for usage details. 

**Demos:**

- [MEDUSA | Android Penetration tool](https://www.youtube.com/watch?v=4hpjRuNJNDw) (credits [@ByteTheories](https://www.youtube.com/@ByteTheories))
- [MEDUSA | Android Malware Analysis 101](https://www.youtube.com/watch?v=kUqucdkVtSU) (credits [@ByteTheories](https://www.youtube.com/@ByteTheories))
- [Unpacking Android malware with Medusa](https://www.youtube.com/watch?v=D2-jREzCE9k) (credits [@cryptax](https://twitter.com/cryptax))
- [Unpacking Android APKs with Medusa](https://www.youtube.com/watch?v=ffM5R2Wfl0A) (credits [@LaurieWired](https://twitter.com/LaurieWired))
- [#Medusa - Extensible binary instrumentation framework based on #FRIDA for Android applications](https://www.youtube.com/watch?v=Hon7zETJawA) (credits [@AndroidAppSec](https://www.youtube.com/@AndroidAppSec))
- [Memory inspection with Medusa](https://www.youtube.com/watch?v=odt21wiUugQ)
- [Bypassing root detection](https://twitter.com/ch0pin/status/1381216805683924994)

## Quick start

### Using medusa.py

The main idea behind MEDUSA is to be able to add or remove hooks for Java or Native methods in a large scale while keeping the process simple and effective. MEDUSA has **more than** **90** modules which can be combined, each one of them dedicated to a set of tasks. Indicatively, some of these tasks include:

-  SSL pinning bypass
-  UI restriction bypass (e.g. Flag secure, button enable)
-  Class enumeration
-  Monitoring of:
   -  Encryption process (keys, IVs, data to be encrypted)
   -  Intents
   -  Http communications
   -  Websockets
   -  Webview events
   -  File operations
   -  Database interactions
   -  Bluetooth operations
   -  Clipboard
-  Monitoring of API calls used by malware applications, such as:
   -  Spyware
   -  Click Fraud
   -  Toll Fraud
   -  Sms Fraud
   
Furthermore, you can intercept Java or Native methods that belong to 3rd party apps or create complex frida modules with just few simple commands.

### Using mango.py

Mango is medusa's twin brother which can be used to:

- Parse and analyse the Android manifest
- Enumerate an application's attack entry points (exported activities, deeplinks, services etc.)
- Keep track of all your analysed applications
- Automate boring processes like: 
  - Set up a MITM
  - Patching 
  - Wrap adb commands 
  - Set/View/Reset the device's proxy configuration
  
...and many many more


# Contribute by:

- Making a pull request
- Creating a medusa module (see [how to](https://github.com/Ch0pin/medusa/wiki/Medusa#creating-a-medusa-module))
- Reporting an error/issue 
- Suggesting an improvement
- Making this project more popular by sharing it or giving a star

# Screenshots

#### - SSL Unpinning

![ssl unpinning](https://user-images.githubusercontent.com/4659186/151658672-dc80f37c-f4fb-48b8-a355-1dc0bf2b172c.png)

#### - Intent Monitoring 

![Intent monitoring](https://user-images.githubusercontent.com/4659186/225246566-ad1e7de0-0c74-4da9-ae01-ba3fec9661a0.png)

#### - Webview Monitoring

![Webview monitoring](https://user-images.githubusercontent.com/4659186/225247047-f25fde47-671f-4e94-99d6-54996678e770.png)


#### - File/Content provider monitoring

![File and content providers](https://user-images.githubusercontent.com/4659186/225247734-69a58b7a-1318-4f7c-a877-6c95cdf8b07d.png)


#### - Native Libraries Enumeration

![Screenshot 2020-09-22 at 16 41 10](https://user-images.githubusercontent.com/4659186/151658663-6c77f2e3-6f42-4424-b593-d8cfe3d3bed3.png)

#### - Memory READ/WRITE/SEARCH (interactive mode):

![Screenshot 2020-09-22 at 16 41 10](https://user-images.githubusercontent.com/4659186/151658659-b4f83296-60ec-4818-a303-5645284b0a67.png)

#### - Personal information exfiltration monitoring

> Hooks api calls which found to be common for this kind of malware, including:
> - Contact exfiltration 
> - Call log exfiltration
> - Camera usage
> - Microphone usage
> - Location tracking
> - File uploading
> - Media recording
> - Clipboard tracking
> - Device recon
> - Screenshot capture

<img src="https://user-images.githubusercontent.com/4659186/87245281-1c4b4c00-c43c-11ea-9cad-195ceb42794a.png" width="450" height="460">

#### - Translation 

> Translates the application's UI by hooking 'setText' calls  

<img src="https://user-images.githubusercontent.com/4659186/86785673-e59bbd00-c05a-11ea-8fb0-9c3f86043104.png" width="250" height="450">                             <img src="https://user-images.githubusercontent.com/4659186/86785688-e9c7da80-c05a-11ea-838f-e4c7568c7c2a.png" width="250" height="450">     


<img src="https://user-images.githubusercontent.com/4659186/86785693-eb919e00-c05a-11ea-901e-8cc180d6274a.png" width="550" height="250">


## Using Stheno (Σθενώ) with Medusa

[Stheno](https://github.com/Ch0pin/stheno) is a subproject of Medusa, specifically designed for intent monitoring within this framework. Below is a quick guide on how to set up and use Stheno effectively.

<p align="center">
  <img src="https://github.com/Ch0pin/stheno/assets/4659186/fd49c39e-865b-4dc3-b2d1-59a0f4594028" alt="monitor" width="400"/>
</p>

1. **Include the Intent Module**:
   Add the `intents/start_activity` module to your Medusa project:
   ```bash
   medusa> add intents/start_activity
   ```

2. **Run the Socket Server**:
   Start the Medusa socket server to facilitate communication:
   ```bash
   medusa> startserver
   ```

3. **Launch Stheno**:
   Open Stheno and navigate to the Intent Monitor menu, then click on **Start** to begin monitoring intents.


**CREDITS**:

- Special Credits to [@rscloura](https://github.com/rscloura) for his contributions
- Logo Credits: https://www.linkedin.com/in/rafael-c-ferreira
- https://github.com/frida/frida
- https://github.com/dpnishant/appmon
- https://github.com/brompwnie/uitkyk
- https://github.com/hluwa/FRIDA-DEXDump.git
- https://github.com/shivsahni/APKEnum
- https://github.com/0xdea/frida-scripts
- https://github.com/Areizen/JNI-Frida-Hook