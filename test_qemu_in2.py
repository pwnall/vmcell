import socket, json, time, subprocess, os

qmp_path = "/tmp/qemu-test/qmp.sock"
if os.path.exists(qmp_path):
    os.remove(qmp_path)

p = subprocess.Popen(["qemu-system-x86_64", "-qmp", f"unix:{qmp_path},server,nowait", "-nographic", "-incoming", "defer"])
time.sleep(1)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(qmp_path)
s.send(b'{"execute": "qmp_capabilities"}\n')
print(s.recv(1024))

s.send(b'{"execute": "migrate-incoming", "arguments": {"uri": "file:/tmp/qemu-test/state.bin"}}\n')

# print events
s.settimeout(0.5)
for _ in range(5):
    try:
        s.send(b'{"execute": "query-migrate"}\n')
        print(s.recv(1024))
    except Exception as e:
        print(e)
    time.sleep(0.5)

p.kill()
