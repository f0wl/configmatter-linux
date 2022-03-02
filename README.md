# ConfigMatter-linux

ConfigMatter-linux is a static configuration extractor implemented in Golang for BlackMatter Ransomware (targeting GNU/Linux and VMware ESXi). By default the script will print the extracted information to stdout (using the ```-v``` (verbose) or ```-d``` (debug) flag is recommended for deeper investigations (hexdump, debug information in case of errors). It is also capable of dumping the malware configuration to disk as a JSON file with the ```-j``` flag.

### Usage 

```shell
go run configmatter-linux.go blackmatter-linux_structs.go [-v] [-d] [-j] path/to/sample.elf
```
### Screenshots

![Running the script](img/tool.png)

## Configuration structure

The configuration of BlackMatter is stored as a Base64 string in the ```.cfgETD``` section for the encryptor and ```.cfgDTD``` for the decryptor. The next layer is zlib compression (the Windows version uses APlib). Once it is decompressed you will be presented with a rolling XOR encryption where the first 32 bytes of the data are the key.

![Running the script](img/config-layers.png)

### Encryptor

The configuration of the encryptor contains the following data:

|         Value         |             Description             |
|-----------------------|-------------------------------------|
| rsa                   | RSA public key                      |
| remove-self           | Switch for self-deletion            |
| worker-concurrency    | Threading                           |
| disk.enable           | Switch for file encryption          |
| disk.type             | Storage type to encrypt             |
| disk.dark-size        | Number of bytes to encrypt          |
| disk.white-size       | Number of bytes to skip             |
| disk.min-size         | Minimum amount of data to encrypt   |
| disk.extension-list   | File extensions                     |
| log.enable            | Switch for logging                  |
| log.level             | Verbosity level of the log          |
| log.path              | Filepath of the log file            |
| message.enable        | Swtich for the ransomnote           |
| message.file-name     | Filename of the ransomnote          |
| message.file-content  | Contents of the ransomnote          |
| landing.enable        | Switch for C2 communication         |
| landing.bot-id        | Campaign ID                         |
| landing.key           | AES Key for C2 communication        |
| landing.urls          | C2 URLs                             |
| kill-vm.enable        | Switch for VM shutdown              |
| kill-vm.ignore-list   | Exceptions from VM shutdown         |
| kill-process.enable   | Switch for process termination      |
| kill-process.list     | List of processes to terminate      |

### Decryptor

The configuration of the decryptor contains the following data:

|         Value         |             Description             |
|-----------------------|-------------------------------------|
| rsa                   | RSA private key                     |
| remove-self           | Switch for self-deletion            |
| worker-concurrency    | Threading                           |
| disk.enable           | Switch for file decryption          |
| disk.type             | Storage type to decrypt             |
| disk.dark-size        | Number of bytes to decrypt          |
| disk.white-size       | Number of bytes to skip             |
| disk.min-size         | Minimum amount of data to decrypt   |
| disk.extension-list   | File extensions                     |
| log.enable            | Switch for logging                  |
| log.level             | Verbosity level of the log          |
| log.path              | Filepath of the log file            |
| message.enable        | Swtich for the ransomnote           |
| message.file-name     | Filename of the ransomnote          |

## Testing

This configuration extractor has been tested successfully with the following samples:

|                             SHA-256                              |                     Sample                              |  Version |
| :--------------------------------------------------------------: | :-----------------------------------------------------: | :------: |
| 1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f | [VirusTotal](https://www.virustotal.com/gui/file/1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f) | 1.6.0.2 |
| 6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502 | [VirusTotal](https://www.virustotal.com/gui/file/6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502) | 1.6.0.2 |
| e48c87a1bb47f60080320167d73f30ca3e6e9964c04ce294c20a451ec1dff425 | [VirusTotal](https://www.virustotal.com/gui/file/e48c87a1bb47f60080320167d73f30ca3e6e9964c04ce294c20a451ec1dff425) | 1.6.0.2 |
| d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82 | [VirusTotal](https://www.virustotal.com/gui/file/d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82) | 1.6.0.4 |

If you encounter an error with ConfigMatter, please file a bug report via an issue. Contributions are always welcome :)
