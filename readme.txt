1.project
    离线ps文件验证服务
2.start
    运行docker目录下build_image.sh脚本，制作镜像和启动容器
3.http接口
    POST  http://192.168.56.10:8089/sign/start
    request body:
        {
            "streamFile": "/workspace/223_2.ps",
            "certFile": "/workspace/13100000001181000223_sign.cer"
        }
    response body:
        {
            "failFrames": [
                {
                    "offset": "1",
                    "time": "2024-3-13T10:52:59.015"
                }
            ],
            "signFail": 1,
            "signSuc": 15,
            "streamId": "1310000000132200022"
        }