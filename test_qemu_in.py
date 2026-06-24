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
while True:
    try:
        res = s.recv(4096)
        if not res: break
        print(res)
    except socket.timeout:
        s.send(b'{"execute": "query-status"}\n')
        print(s.recv(1024))
        break

p.kill()
