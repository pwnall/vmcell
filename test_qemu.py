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

s.send(b'{"execute": "migrate", "arguments": {"uri": "file:/tmp/qemu-test/state.bin"}}\n')
print(s.recv(1024))

while True:
    s.send(b'{"execute": "query-migrate"}\n')
    res = s.recv(1024)
    print(res)
    if b"completed" in res or b"failed" in res:
        break
    time.sleep(0.5)

p.kill()
