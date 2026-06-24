import socket, json, time, subprocess, os

os.makedirs("/tmp/qemu-test", exist_ok=True)
qmp_path = "/tmp/qemu-test/qmp.sock"
if os.path.exists(qmp_path):
    os.remove(qmp_path)

p = subprocess.Popen(["qemu-system-x86_64", "-qmp", f"unix:{qmp_path},server,nowait", "-nographic"])
time.sleep(1)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(qmp_path)
s.send(b'{"execute": "qmp_capabilities"}\n')
print(s.recv(1024))

s.send(b'{"execute": "cont"}\n')
print(s.recv(1024))
