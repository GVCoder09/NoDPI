<div align="center">
  <p>
    <a href="#"><img src="./assets/ico.png" height="150px" alt="logo" /></a>
  </p>
</div>


# NoDPI
*Say NO to blocking!*

[![Visitors](https://visitor-badge.laobi.icu/badge?page_id=GVCoder09.NoDPI)]()

> [!IMPORTANT]
> This project is a fork of the repository https://github.com/theo0x0/nodpi and is developed independently. Do not confuse with https://github.com/raspabamos/nodpi !

[**Available version for Android!**](https://github.com/GVCoder09/NoDPI4Android)

## Description / Описание
NoDPI is a utility for bypassing the DPI (Deep Packet Inspection) system. DPI is widely used by Internet providers and government agencies to block access to Internet resources. This utility allows you to bypass such blocking and freely use the Internet. In particular, it allows you to eliminate the blocking of YouTube in Russia.

Unfortunately, I cannot guarantee the absolute functionality of the program in all conditions and with all providers, but in most cases it copes with its task perfectly.
The utility works on the principle of an HTTP proxy. It analyzes all TLS handshakes passing through it and fragments them if they are addressed to blocked domains. Currently, DPI does not have the capacity to collect these fragments and analyze them, so NoDPI manages to "fool" it.

The utility does not collect or send any data and does not require administrator privileges to run.

The entire code is written entirely in Python and does not use third-party dependencies.

<hr>

NoDPI - это утилита для обхода системы DPI (Deep Packet Inspection). DPI широко используется интерент-провайдерами и гос. органами для блокировки доступа к интерент-ресурсам. Данная утилита позволяет обходить такие блокировки и свободно пользоваться Интернетом. В частности, она позволяет устранить блокировку YouTube в России.

К сожалению, я не могу гарантировать абсолютную работоспособность программы во всех условиях и у всех провайдеров, но в большинстве случаев она отлично справляется со своей задачей.

Утилита работает по принципу HTTP прокси. Она анализирует все  проходящие через нее TLS handshake и фрагментирует их, если они адресованы заблокированным доменам. В настоящее время у DPI нет таких мощностей, чтобы собиртаь эти фрагменты и анализировать их, поэтому NoDPI получается ее "обмануть".

Утилита не собирает и не отправляет никаких данных и не требует привелегий администратора для запуска.

Весь код полностью написан на языке Python и не использует сторонних зависимостей.

[![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/217/1ff/871/2171ff87152a613fa85bfc83d2669469.png)]()

### Alternatives / Альтернативы 
- **[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)** by @ValdikSS (for Windows)
- **[zapret](https://github.com/bol-van/zapret)** by @bol-van (for MacOS, Linux and Windows)
- **[Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel)** by @SadeghHayeri (for MacOS, Linux and Windows)
- **[DPI Tunnel CLI](https://github.com/nomoresat/DPITunnel-cli)** by @zhenyolka (for Linux and routers)
- **[DPI Tunnel for Android](https://github.com/nomoresat/DPITunnel-android)** by @zhenyolka (for Android)
- **[PowerTunnel](https://github.com/krlvm/PowerTunnel)** by @krlvm (for Windows, MacOS and Linux)
- **[PowerTunnel for Android](https://github.com/krlvm/PowerTunnel-Android)** by @krlvm (for Android)
- **[SpoofDPI](https://github.com/xvzc/SpoofDPI)** by @xvzc (for macOS and Linux)
- **[SpoofDPI-Platform](https://github.com/r3pr3ss10n/SpoofDPI-Platform)** by @r3pr3ss10n (for Android, macOS, Windows)
- **[GhosTCP](https://github.com/macronut/ghostcp)** by @macronut (for Windows)
- **[ByeDPI](https://github.com/hufrea/byedpi)** for Linux/Windows + **[ByeDPIAndroid](https://github.com/dovecoteescapee/ByeDPIAndroid/)** for Android (no root)
- **[youtubeUnblock](https://github.com/Waujito/youtubeUnblock/)** by @Waujito (for OpenWRT/Entware routers and Linux)

## Terms of Use and Disclaimer / Условия использования и отказ от ответственности
> [!IMPORTANT]
> This provision is in addition to the license and takes precedence over it.

The developer and/or supplier of this software shall not be liable for any loss or damage, including but not limited to direct, indirect, incidental, punitive or consequential damages arising out of the use of or inability to use this software, even if the developer or supplier has been advised of the possibility of such damages.

The developer and/or supplier of this software shall not be liable for any legal consequences arising out of the use of this software. This includes, but is not limited to, violation of laws, rules or regulations, as well as any claims or suits arising out of the use of this software. The user is solely responsible for compliance with all applicable laws and regulations when using this software.

The developer and/or supplier of this software shall not be liable for any loss or damage arising out of the unauthorized use of this software. Unauthorized use includes, but is not limited to, using the software for illegal purposes, infringing copyrights, patents, trademarks or other intellectual property rights, or using the software in violation of the license terms of the software.

This software may not be used for illegal or unlawful purposes. Any use of the software for illegal activities, including but not limited to fraud, hacking, privacy violation, distribution of malware or any other actions contrary to the code and regulations is strictly prohibited. The user is fully responsible for any legal consequences arising from the use of this software for illegal purposes.

Your use of this software constitutes your agreement to the terms of this disclaimer. If you do not agree to these terms, you must stop using this software immediately.

<hr>

> [!IMPORTANT]
> Данное положение является дополнением к лицензии и является приоритетным по отношению к ней.

Разработчик и/или поставщик данного программного обеспечения не несет никакой ответственности за любые убытки или ущерб, включая, но не ограничиваясь, прямые, косвенные, случайные, штрафные или косвенные убытки, возникшие в результате использования или невозможности использования данного программного обеспечения, даже если разработчик или поставщик были уведомлены о возможности таких убытков.

Разработчик и/или поставщик данного программного обеспечения не несут ответственности за любые юридические последствия, возникшие в результате использования данного программного обеспечения. Это включает, но не ограничивается, нарушение законодательства, правил или нормативных актов, а также любые претензии или иски, возникшие в результате использования данного программного обеспечения. Пользователь несет полную ответственность за соблюдение всех применимых законов и нормативных актов при использовании данного программного обеспечения.

Разработчик и/или поставщик данного программного обеспечения не несут ответственности за любые убытки или ущерб, возникшие в результате неправомерного использования данного программного обеспечения. Неправомерное использование включает, но не ограничивается, использование программного обеспечения для незаконных целей, нарушение авторских прав, патентных прав, торговых марок или других прав интеллектуальной собственности, а также использование программного обеспечения в нарушение условий лицензии данного программного обеспечения.

Данное программное обеспечение не может использоваться в противоправных целях или целях, нарушающих законодательство. Любое использование программного обеспечения для незаконных действий, включая, но не ограничиваясь, мошенничество, взлом, нарушение конфиденциальности, распространение вредоносного ПО или любые другие действия, противоречащие закодательству и нормативным актам, строго запрещено. Пользователь несет полную ответственность за любые юридические последствия, возникшие в результате использования данного программного обеспечения в противоправных целях.

Использование данного программного обеспечения означает ваше согласие с условиями данного отказа от ответственности. Если вы не согласны с этими условиями, вы должны немедленно прекратить использование данного программного обеспечения.

## Quick start / Быстрый старт
1) Download the latest version for your OS from [the Releases page](https://github.com/GVCoder09/NoDPI/releases) and unzip it
2) Go to the directory with the unzipped utility and run it with the command `nodpi.exe --blacklist blacklist.txt` in Windows or `./nodpi --blacklist ./blacklist.txt` in Linux. You can replace the file `blacklist.txt` with your own file. **If the blacklist file is not specified, the program will search for the file `blacklist.txt` in the current directory by default.**
3) In the browser or system settings, set the proxy to 127.0.0.1:8881
4) In some browsers, you may need to disable kyber
5) Enjoy!

> [!IMPORTANT]
> Don't forget to disable the proxy in your system and browser settings after closing the program!

Please report any problems and malfunctions to us on [the Issues page](https://github.com/GVCoder09/NoDPI/issues)

<hr>

1) [Скачайте](https://github.com/GVCoder09/NoDPI/releases) последнюю версию утилиты для вашей ОС и разархивруйте ее
2) Перейдите в каталог с распакованной утилитой и запустите ее командой `nodpi.exe --blacklist blacklist.txt` в Windows или `./nodpi --blacklist ./blacklist.txt` в Linux. Вы можете заменить файл `blacklist.txt` своим файлом. **Если файл черного списка не указан, то программа по умолчанию будет искать файл `blacklist.txt` в текущей директории.**
3) В настройках браузера или системы настройте прокси на 127.0.0.1:8881
4) В некоторых браузерах может потребоваться отключение kyber
5) Наслаждайтесь!

> [!IMPORTANT]
> Не забудьте отключить прокси в настройках системы и браузера после закрытия программы!

О всех проблемах и неполадках, пожалуйста, сообщайте нам в [Issues](https://github.com/GVCoder09/NoDPI/issues)

## Add to startup (only for Windows) / Добавление в автозагрузку (только для Windows)
1) [Download](https://github.com/GVCoder09/NoDPI/releases) the latest version of the utility for Windows and unzip it
2) Go to the directory with the unzipped utility. Move the `blacklist.txt` file to the same folder where the program itself is located.
3) Run the command `nodpi.exe --install`. The program will be added to startup via the Windows registry (`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`)
4) Restart your computer
5) Enjoy!

<hr>

1) [Скачайте](https://github.com/GVCoder09/NoDPI/releases) последнюю версию утилиты для Windows и разархивруйте ее
2) Перейдите в каталог с распакованной утилитой. Переместите файл `blacklist.txt` в ту же папку, где находится сама программа
3) Запустите команду `nodpi.exe --install`. Программа будет добавлена в автозагрузку через реестр Windows (`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`)
4) Перезагрузите компьютер
5) Наслаждайтесь!

## Supported arguments / Поддерживаемые аргументы командной строки
```
usage: nodpi [-h] [--host HOST] [--port PORT] 
             [--blacklist BLACKLIST | --no_blacklist] 
             [--log_access LOG_ACCESS] [--log_error LOG_ERROR] 
             [-q] [-v] [--install | --uninstall]

options:
  -h, --help            show this help message and exit
  --host HOST           Proxy host
  --port PORT           Proxy port
  --blacklist BLACKLIST
                        Path to blacklist file
  --no_blacklist        Use fragmentation for all domains
  --log_access LOG_ACCESS
                        Path to the access control log
  --log_error LOG_ERROR
                        Path to log file for errors
  -q, --quiet           Remove UI output
  -v, --verbose         Show more info (only for devs)
  --install             Add proxy to Windows autostart (only for EXE)
  --uninstall           Remove proxy from Windows autostart (only for EXE)

```
## Run from source code / Запуск из исходного кода

1) Make sure you have Python 3.8 or higher installed. No third-party libraries are required
2) Clone the repository `git clone https://github.com/GVCoder09/NoDPI.git` or [download the archive](https://github.com/GVCoder09/NoDPI/archive/refs/heads/main.zip) with the source code and unzip it
3) Go to the main directory and run the code with the command `python src/main.py --blacklist ./blacklist.txt`
3) In the browser or system settings, set the proxy to 127.0.0.1:8881
4) In some browsers, you may need to disable kyber
5) Enjoy!

You can enable error or access logging using parameters `--log_error` and `--log_access`

<hr>

1) Убедитесь что у вас установлен Python версии 3.8 и выше. Никакие сторонние библиотеки не требуются
2) Клонируйте репозиторий `git clone https://github.com/GVCoder09/NoDPI.git` или [скачайте архив](https://github.com/GVCoder09/NoDPI/archive/refs/heads/main.zip) с исходным кодом и распакуйте его
3) Перейдите в основную директорию и запустите код командой `python src/main.py --blacklist ./blacklist.txt`
3) В настройках браузера или системы настройте прокси на 127.0.0.1:8881
4) В некоторых браузерах может потребоваться отключение kyber
5) Наслаждайтесь!

Вы можете включить логирование ошибок или доступа с помощью параметров `--log_error` и `--log_access`

## Running in Docker / Запуск в Docker

1) [Install Docker](https://docs.docker.com/).
2) Clone the repository: `git clone https://github.com/GVCoder09/NoDPI`
3) Navigate to the project directory and build the container: `cd NoDPI && docker build -t nodpi .`
4) Run the container with the command: `docker run -d -p 127.0.0.1:8881:8881 -v /path/to/blacklists/:/blacklists:ro nodpi`, where `/path/to/blacklists/` is the path to the blacklist files.
5) Enjoy!

<hr>

1) [Установите Docker](https://docs.docker.com/)
2) Склонируйте репозиторий: `git clone https://github.com/GVCoder09/NoDPI`
3) Перейдите в директорию проекта и соберите контейнер: `cd NoDPI && docker build -t nodpi .`
4) Запустите контейнер с помощью команды: `docker run -d -p 127.0.0.1:8881:8881 -v /path/to/blacklists/:/blacklists:ro nodpi`, где `/path/to/blacklists/` путь к файлам с черными списками
5) Наслаждайтесь!

## Known bugs / Известные проблемы

- Doesn't work at all. Yes, that can happen :(
- Doesn't bypass IP block
- Only TCP and HTTPS (HTTP ignored)
- Not working with sites with old TLS

<hr>

- Не работает вообще. Да, такое может быть :(
- Не работает, если сайт заблокирован по IP
- Только для TCP и HTTPS (HTTP игнорируется)
- Не работает для сайтов со старым TLS

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=GVCoder09/NoDPI&type=Date)](https://www.star-history.com/#GVCoder09/NoDPI&Date)

## Thanks to the project participants / Благодарность участникам проекта

[![Contributors](https://contrib.rocks/image?repo=GVCoder09/NoDPI)](https://github.com/GVCoder09/NoDPI/graphs/contributors)


