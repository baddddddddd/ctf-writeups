Summary:
1. There is an exposed `/.git` folder, download that recursively using `wget -r <link>`
2. Open the download folder in VSCode for easy navigation of git logs.
3. Find the leaked admin credentials
4. Visit the login page was moved from `/ServerMonitor` to `/servermonitor`
5. Login there using the leaked admin credentials
6. Use Command Injection in the `count` field to print `/flag.txt`
7. 