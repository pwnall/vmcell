# **Architectural Blueprint for the Imp Agentic Evaluation Platform**

The evaluation and integration testing of autonomous agentic systems, such as the Imp harness, demands execution environments that satisfy seemingly contradictory requirements: they must provide hardware-level isolation to prevent state leakage and malicious host compromise, yet they must boot and tear down in milliseconds to support high-throughput testing pipelines. Furthermore, because agentic systems dynamically interact with file systems, execute arbitrary generated code, and establish network connections, traditional Linux namespace containerization (e.g., Docker) is fundamentally inadequate as a security boundary1. A kernel exploit within a shared-kernel container results in immediate host compromise1.
To provide a deterministic, ephemeral, and secure evaluation platform, the architecture must transition to micro-virtual machines (micro-VMs). Micro-VMs leverage the Linux Kernel-based Virtual Machine (KVM) to provide dedicated guest kernels and hardware-enforced isolation per test, whilst aggressively stripping out legacy hardware emulation to achieve container-like boot speeds3. This report details the end-to-end architectural design for the Imp integration platform, systematically evaluating Virtual Machine Monitors (VMMs), Rust-based control planes, filesystem sharing mechanics, transparent network interception, and aggressive guest operating system optimization.

## **Virtual Machine Monitor (VMM) Landscape Analysis**

The core of the evaluation platform relies on the VMM responsible for interacting with /dev/kvm and managing the guest execution. Traditional hypervisors like QEMU are vast, general-purpose emulators consisting of over two million lines of C code, burdened by decades of legacy device support (e.g., floppy drives, PCI buses, VGA) which inflate boot times to several seconds5. For the Imp platform, the VMM must be selected from the modern rust-vmm ecosystem, a collection of virtualization components written in memory-safe Rust that prioritize minimalism and speed7.
The primary technologies under consideration are AWS Firecracker, Kata Containers, and Cloud Hypervisor.

### **AWS Firecracker**

Developed by Amazon Web Services to power Lambda and Fargate, Firecracker is the pioneer of the micro-VM movement3. It is written entirely in Rust and is designed with strict minimalism, containing approximately 50,000 lines of code4. Firecracker implements only five paravirtualized devices: virtio-net, virtio-block, virtio-vsock, a serial console, and a minimal keyboard controller used exclusively for sending termination signals3.
This minimalism allows Firecracker to achieve remarkable performance characteristics. It boots to guest userspace in approximately 125 milliseconds and imposes a memory overhead of less than 5 MiB per micro-VM, allowing thousands of instances to be packed onto a single physical host3. Furthermore, it includes a companion process called the jailer, which wraps the VMM in Linux cgroups, namespaces, and strict seccomp-bpf filters to provide defense-in-depth against virtualization boundary escapes4.
However, Firecracker's strict minimalism introduces severe architectural constraints for the Imp evaluation platform. Most notably, Firecracker explicitly refuses to implement filesystem sharing protocols like virtio-fs or 9pfs in order to minimize its attack surface12. To provide the Imp guest with data, the host platform must format input data and binaries into raw ext4 or squashfs block devices, attach them via virtio-block, and mount them internally14. This completely precludes the requirement for "easy" shared directories with granular, on-the-fly access permissions, rendering Firecracker suboptimal for highly dynamic integration testing where host-guest file sharing is a primary integration vector.

### **Kata Containers**

Kata Containers is frequently cited alongside Firecracker, but it occupies a different layer of the virtualization stack. Kata is not a VMM itself; rather, it is an Open Container Initiative (OCI) compliant container runtime that wraps virtual machines5. When a system requests a container deployment, Kata intercepts the request and launches a VMM—which can be QEMU, Firecracker, or Cloud Hypervisor—to run the workload inside a hardware-isolated boundary13.
While Kata natively supports virtio-fs (when paired with a compatible backend VMM) and transparently handles networking through container orchestration plugins (CNI), it introduces an orchestration overhead. Boot times via Kata range from 150 to 300 milliseconds due to the translation between OCI container specifications and hypervisor configurations16. Because the Imp harness is being driven natively from a custom Rust codebase, interposing Kata Containers adds an unnecessary layer of orchestration complexity. The platform benefits more from direct, programmatic control over the underlying VMM rather than abstracting it behind Kubernetes or Docker interfaces.

### **Cloud Hypervisor**

Cloud Hypervisor, originally spearheaded by Intel and now managed by the Linux Foundation, represents the optimal middle ground between Firecracker's serverless minimalism and QEMU's legacy bloat6. Built on the same rust-vmm crates as Firecracker, Cloud Hypervisor is specifically designed for modern cloud workloads6. It achieves boot-to-userspace latencies of under 100 milliseconds and supports both KVM and Microsoft Hypervisor (MSHV) backends16.
Crucially, Cloud Hypervisor delegates device emulation to external processes via the vhost-user protocol22. This architectural decision allows it to natively support vhost-user-fs (virtio-fs), seamlessly fulfilling the requirement for shared host directories13. Furthermore, it supports direct kernel booting, advanced memory hotplugging, and dynamic resizing of virtual block devices6.

| Feature | AWS Firecracker | Kata Containers | Cloud Hypervisor |
| :---- | :---- | :---- | :---- |
| **Primary Role** | Direct VMM (Micro-VMs) | OCI Container Runtime wrapper | Direct VMM (Cloud workloads) |
| **Language** | Rust | Go / Rust | Rust |
| **Startup Latency** | \~125ms | 150-300ms (Orchestration overhead) | \<100ms |
| **Host Directory Sharing** | Unsupported (Requires Block Devices) | Supported via backend VMM | Native via virtio-fs (vhost-user-fs) |
| **Network Overhead** | Low (virtio-net) | Low (Varies by backend) | Low (virtio-net / vhost-user-net) |
| **Nested Virtualization** | Supported (Guest access to KVM) | Supported | Supported |
| **Optimal Use Case** | Stateless FaaS / Lambda | Kubernetes secure isolation | Stateful / Custom VM orchestration |

Given the strict requirement for shared directories with distinct access permissions, the need for deep programmatic control via Rust, and the necessity of millisecond-level boot times, Cloud Hypervisor is the definitive choice for the Imp evaluation platform's virtualization engine.

## **Rust Control Plane and Artifact Management**

The Imp integration platform must orchestrate the entire lifecycle of the micro-VM from a cohesive Rust codebase. This involves managing the execution states (creation, start, pause, destroy), configuring virtualized hardware, and generating the necessary runtime artifacts.

### **Managing the Virtual Machine Lifecycle**

Both Firecracker and Cloud Hypervisor expose their control planes through REST APIs served over Unix Domain Sockets3. This decoupling separates the data plane (the vCPU threads executing guest code) from the control plane (the API thread), ensuring security and stability4.
To drive Cloud Hypervisor programmatically from Rust, the platform leverages the cloud-hypervisor-client crate. This library is auto-generated from the Cloud Hypervisor OpenAPI specification, providing strongly typed, asynchronous interfaces to manage the VMM28. The execution flow operates as a deterministic state machine:

1. **Instantiation**: The Rust harness launches the cloud-hypervisor binary in an idle API-only mode, passing an \--api-socket path26.
2. **Configuration**: The harness issues asynchronous PUT requests via cloud-hypervisor-client to configure the VmConfig payload. This defines the vCPUs, memory, direct kernel boot parameters (vmlinux path), network TAP interfaces, and virtio-fs socket paths27.
3. **Execution**: A PUT request to the /api/v1/vm.boot endpoint transitions the virtual machine into a running state27.
4. **Teardown**: Following test completion, the harness invokes /api/v1/vm.shutdown for a graceful ACPI shutdown, or aggressively terminates the VMM process for an immediate force-stop26.

For environments where Firecracker might be utilized as a fallback or for specific test scenarios, the firecracker-rs-sdk provides an analogous Rust experience. It abstracts the Firecracker REST API, offering robust methods for instance management (start, pause, resume, stop) and configuration of CPU models, virtio-net interfaces, and rate limiters30. The firepilot crate serves as an alternative, offering higher-level Machine abstractions for lifecycle management31.

### **Generating Virtualization Artifacts**

Before booting the VM, the test platform must generate filesystems, configuration files, and network configurations. The herolib-virt Rust crate provides a Service Abstraction Layer (SAL) for managing these virtualization artifacts across platforms. It exposes modules for creating QCOW2 disk images (qcow2), interacting with Cloud Hypervisor (cloudhv), and managing high-performance directory sharing (virtiofsd)32.
While Cloud Hypervisor natively supports QCOW2 images with thin-allocation and read-only overlay semantics (saving massive amounts of host disk capacity compared to Firecracker's raw image requirement)24, the primary mechanism for injecting the Imp agent and its data relies entirely on paravirtualized file systems rather than block devices.

## **Filesystem Architecture and Data Sharing**

Providing the Imp guest with full access to the host's testing data, while maintaining absolute isolation and granular permission boundaries, is achieved via virtio-fs. This technology exposes a local file system interface over virtual queues, avoiding the immense overhead associated with traditional network file systems like NFS or 9pfs33.

### **The virtiofsd Daemon Integration**

The core of virtio-fs relies on a host-side daemon, virtiofsd, which processes FUSE (Filesystem in Userspace) requests originating from the guest kernel34. The modern implementation of virtiofsd is written entirely in Rust, maximizing memory safety when handling potentially malicious system calls from the untrusted Imp guest35.
To fulfill the requirement for separate access permissions (input data, output data, and Imp binaries), the Rust test harness spawns multiple isolated instances of the virtiofsd daemon prior to booting the Cloud Hypervisor VM23.

1. **Input Data and Binaries (Read-Only)**: The harness launches virtiofsd instances targeting the test input directory and the build artifacts directory. Crucially, these instances are spawned with the \--readonly command-line flag35. This enforces a hard, host-level restriction preventing write access from the guest, guaranteeing that a runaway or malicious Imp test cannot corrupt the shared datasets or tamper with the compiled binaries37.
2. **Output Data (Read-Write)**: A separate virtiofsd instance is launched targeting an ephemeral, per-test host directory without the read-only restriction. This allows the Imp agent to persist logs, telemetry, and output artifacts back to the host filesystem for post-test assertion analysis37.

Each daemon binds to a distinct UNIX domain socket (e.g., /tmp/imp\_in.sock, /tmp/imp\_out.sock). During the VM configuration phase, the cloud-hypervisor-client API assigns each socket to a distinct mount tag within the guest23. The guest OS utilizes standard fstab entries to mount these tags to their respective internal paths (/mnt/input, /mnt/output)33.

### **DAX (Direct Access) Optimization**

To achieve extreme memory density and boot performance, the virtio-fs mounts leverage Direct Access (DAX). DAX allows the guest virtual machine to map file contents directly into a shared memory window on the host, completely bypassing the guest's internal page cache34.
Because the Imp binaries and input test data are identical across concurrent test runs and marked as read-only, DAX enables the host Linux kernel to load these physical memory pages precisely once. Subsequent Cloud Hypervisor instances accessing these files map the same host pages, drastically reducing memory duplication and the occurrence of page faults during boot and execution34. The Rust harness configures this via Cloud Hypervisor's filesystem API, passing parameters such as dax=on and defining a specific cache\_size window23.

## **Network Isolation and Transparent Interception**

The evaluation platform must allow the Imp agent to communicate with integration-test HTTP servers while selectively allowing, logging, and filtering access to the broader internet. Accomplishing this without configuring explicit proxy settings inside the guest requires a robust Layer 2/Layer 3 networking topology and transparent packet interception.

### **TAP Devices and Virtual Bridging**

Cloud Hypervisor utilizes the virtio-net paravirtualized network interface. For every test iteration, the Rust control plane creates a dedicated TAP interface on the host (e.g., tap\_imp\_123) using the iproute2 toolset or equivalent Rust netlink libraries15.
These TAP interfaces are bridged together onto a central host-managed virtual bridge (e.g., imp-br0). The virtual bridge is assigned a static private IP address, which acts as the default gateway for the micro-VMs15.
This topology inherently satisfies the requirement for accessing HTTP servers started by the integration test, as well as the bonus requirement for supporting other protocols. Because the guest receives a full Layer 2 interface, the integration test framework can simply bind its mock servers to the IP address of the host bridge. The Imp agent can subsequently connect to these mock servers using standard routing over TCP, UDP, ICMP, or WebSockets, without traversing the host's external physical network41.

### **Transparent Proxy via nftables**

To monitor and filter external web access, the platform deploys a transparent proxy on the host machine. A transparent proxy intercepts outbound traffic without the proxied device (the guest VM) realizing the interception is occurring43.
Traffic exiting the guest VM via its TAP interface hits the virtual bridge. Before the host kernel routes this traffic to the external internet via NAT masquerading, the packets traverse the host's nftables firewall rules45. The Rust harness dynamically injects Destination Network Address Translation (DNAT) rules into the prerouting chain of the nat table46.
Specifically, the rule intercepts traffic destined for standard web ports (TCP 80 and 443\) that originates from the specific guest TAP interface, and utilizes the redirect statement to alter the destination IP to the host's loopback address and the destination port to the proxy's listening port (e.g., 8080\)46.

Bash
\# Example logic executed by the Rust harness via netlink/nftables API
nft add rule ip nat prerouting iifname "tap\_imp\_123" tcp dport { 80, 443 } redirect to 8080

### **TLS Termination and Logging**

When outbound HTTPS traffic is redirected to the proxy, it is heavily encrypted. For the integration platform to log, filter, and assert against the requested URLs and payloads, the proxy must terminate the TLS connection43.
The transparent proxy acts as a Man-In-The-Middle (MITM). When the Imp agent requests https://api.example.com, the proxy intercepts the request and generates a dynamic SSL certificate for api.example.com on the fly, signed by a custom, self-generated Root Certificate Authority (CA)43.
To prevent the Imp agent's HTTP clients from rejecting these dynamic certificates with SSL validation errors, the custom Root CA certificate must be injected into the guest operating system's trusted certificate store43. The platform automatically handles this by placing the .crt file into a virtio-fs read-only mount, and a custom initialization script inside the guest registers it with update-ca-certificates immediately upon boot43. This architecture guarantees absolute cryptographic visibility into the agent's behavior without modifying the agent's internal network configuration47.

## **Guest Operating System Optimization**

The requirement asks whether a standard Linux environment like Debian requires specialization for a VM environment lasting only seconds or minutes. The emphatic answer is yes: standard, general-purpose Debian cloud images are entirely unsuitable for ephemeral micro-VM execution, suffering boot latencies between 7 to 15 seconds due to unnecessary hardware probing and massive user-space daemon initialization49. To achieve boot-to-execution times under one second, the Debian environment must be radically optimized.

### **The debootstrap Minimal Root Filesystem**

Instead of downloading pre-packaged OS images, the platform utilizes debootstrap to synthesize a hyper-minimal Debian root filesystem from scratch41. This tool retrieves only the absolutely critical packages required to provide a POSIX-compliant Linux environment. This raw directory structure is never compressed into an .img or .qcow2 file; instead, it is served directly to the Cloud Hypervisor guest via a read-only virtio-fs mount. This bypasses the overhead of virtualized block device initialization and immediately leverages DAX memory mapping for lightning-fast file access23.
To allow the Imp agent to modify standard system paths without altering the shared host directory, the guest initialization process mounts an overlayfs. The overlayfs uses the read-only virtio-fs mount as the lowerdir and a memory-backed tmpfs as the upperdir. All writes performed by the agent are caught in RAM and immediately discarded when the VM terminates, guaranteeing zero state leakage between tests2.

### **Direct Kernel Booting**

A major source of latency in traditional virtualization is the firmware boot phase, where a virtual BIOS or UEFI executes a bootloader like GRUB, which subsequently loads the kernel25. Cloud Hypervisor circumvents this entirely via Direct Kernel Boot.
The Rust test harness passes the path to an uncompressed Linux kernel binary (an ELF vmlinux file) directly into the API configuration20. The VMM loads this kernel straight into the guest's physical memory and jumps to its entry point, saving hundreds of milliseconds.
Furthermore, this kernel is custom-compiled. A standard distribution kernel contains thousands of modules for physical hardware that will never exist in a micro-VM. By stripping out support for USB, SATA, Wi-Fi, and legacy PCI, and compiling strictly with support for virtio drivers (virtio-net, virtio-fs, virtio-console), the kernel initialization phase completes in a fraction of a second8. The host passes the required boot configuration directly to the kernel via command-line arguments (e.g., console=hvc0 root=/dev/root rootfstype=virtiofs rw quiet no\_timer\_check tsc=reliable), bypassing any need for internal grub configurations23.

### **Eradicating User-Space Initialization (systemd and cloud-init)**

Even with an optimized kernel, user-space initialization dominates boot time. Profiling a standard Debian boot sequence reveals that services like cloud-init (which stalls waiting for network metadata) and systemd (which launches dozens of background daemons like lvm2-monitor and rsyslog) consume over three seconds of boot latency49.
For a micro-VM intended to last seconds, these tools are entirely unnecessary. The integration platform completely removes systemd and cloud-init from the debootstrap image. In their place, a custom-written Rust initialization binary is deployed as the designated /sbin/init process (PID 1\)49.
This deterministic init binary has a narrow, sequential scope: it mounts proc and sysfs, configures the virtio-net interface with a static IP address to bypass DHCP broadcast delays, mounts the input/output virtio-fs directories, and immediately uses the exec syscall to replace itself with the Imp agent executable49. By stripping out generic operating system overhead, user-space boot latency is reduced from seconds to under 50 milliseconds49.

| Optimization Target | Standard Debian Cloud Image | Platform Optimized Debian | Impact on Boot Time |
| :---- | :---- | :---- | :---- |
| **Bootloader** | UEFI / GRUB | Direct Kernel Boot (vmlinux) | Eliminates \~500ms |
| **Kernel Modules** | General Purpose | Custom minimal virtio-only | Eliminates \~1000ms |
| **Root Filesystem** | Virtual Block Device (QCOW2/RAW) | Read-only virtio-fs \+ overlayfs | Eliminates block I/O latency |
| **Init System** | systemd | Custom Rust Binary (/sbin/init) | Eliminates \~2000ms |
| **Metadata Fetching** | cloud-init | Disabled (Static config) | Eliminates \~1500ms |
| **Networking** | DHCPv4/v6 | Static IP assignment via custom init | Eliminates network stall timeouts |

Data synthesis derived from comprehensive micro-VM boot optimization studies49.

## **Console Emulation and Telemetry Monitoring**

Rigorous evaluation of the Imp agent requires continuous bidirectional communication and precise tracking of its computational footprint. These tasks must be executed from the host without relying on intrusive guest agents.

### **Console Driving via virtio-console**

The requirement specifies an "easy way to drive its console... some TTY emulation or SSH." Running an SSH daemon inside the guest introduces unacceptable boot latency due to daemon initialization, key generation, and cryptographic handshaking protocols49.
Instead, the platform leverages Cloud Hypervisor's virtio-console device. This paravirtualized device provides a high-throughput, low-latency console implementation that avoids the overhead of emulating legacy 16550A serial ports22.
The Rust test harness on the host configures Cloud Hypervisor to bind this virtio-console to a host-side UNIX domain socket22. Inside the guest, the custom Rust init binary attaches standard input, output, and error streams directly to the corresponding /dev/hvc0 character device23. The host test harness asynchronously reads and writes to the domain socket, achieving real-time, programmatic TTY emulation with the Imp agent. This provides instant stdout/stderr capturing and the ability to inject commands without the overhead of network-based protocols.

### **Out-of-Band Performance Monitoring**

Monitoring the performance of the Imp agent—specifically RAM usage, CPU utilization, and Disk/Network I/O—must not interfere with the agent's execution. Running monitoring tools (like top or htop) inside the guest consumes cycles and alters the test environment53.
Because Cloud Hypervisor executes as a standard Linux user-space process on the host, all resources consumed by the guest are directly reflected in the VMM process's footprint3. The Rust test harness leverages host-side libraries, such as procfs, sysinfo, and perf-monitor-rs, to programmatically scrape telemetry54.

* **CPU Usage**: The procfs crate provides interfaces to read /proc/\[pid\]/stat. By tracking the scheduled user and system time of the specific Cloud Hypervisor process and its child vCPU threads, the harness calculates precise CPU utilization percentages55.
* **Memory (RAM) Usage**: The sysinfo crate retrieves the Resident Set Size (RSS) of the VMM process56. To ensure accuracy when utilizing DAX, the harness queries the /proc/\[pid\]/smaps interface to distinguish between the anonymous memory actively allocated by the Imp agent and the shared, file-backed memory mapped from the virtio-fs host files55.
* **I/O Metrics**: Network and Disk I/O throughput are gathered by reading the statistical interfaces of the host-side TAP device and virtiofsd socket queues, or by directly querying the Cloud Hypervisor REST API for virtualized device telemetry27.

## **Nested Virtualization Capabilities**

The platform accommodates the bonus requirement of allowing the Imp harness to execute its own virtual machines from within the test environment. This necessitates nested virtualization, where a hypervisor running inside a guest VM (L1) utilizes the hardware virtualization extensions of the physical host machine (L0) to run a nested guest (L2)58.
Nested virtualization strictly requires that the host physical machine (L0) has hardware virtualization extensions enabled (Intel VT-x or AMD-V) and that the kernel exposes these extensions to guests. If deploying this platform in cloud environments, specific instance families are required. AWS, for example, natively supports nested virtualization on dedicated .metal bare-metal instances, as well as on their 8th-generation virtualized instances (e.g., c8i, m8i, and r8i)11.
The Rust test harness enables this feature by configuring Cloud Hypervisor to pass the virtualization CPUID flags through to the guest via the API parameter \--cpu nested=on (which defaults to enabled on x86\_64 architectures)24. Inside the Debian guest, because the Imp agent operates with root privileges, it possesses read/write access to the exposed /dev/kvm character device11. This hardware-accelerated access allows the Imp harness to seamlessly instantiate its own isolated instances of QEMU or Firecracker, fully satisfying the requirement for executing L2 virtual machines during evaluation tests5.

## **Conclusion**

The architecture of the Imp integration platform represents a highly tuned synthesis of modern virtualization technologies. By discarding traditional containers and legacy hypervisors in favor of Cloud Hypervisor, the platform achieves hardware-enforced isolation with sub-100-millisecond boot times. The strategic implementation of virtiofsd daemons written in Rust provides read-only and read-write directory sharing enhanced by DAX memory mapping, bypassing cumbersome block device management.
Network traffic is routed through virtual bridges and seamlessly intercepted by nftables for transparent proxying and TLS termination, granting absolute visibility into the agent's web interactions. Finally, the total eradication of standard Debian user-space initialization in favor of a direct-booted, custom Rust init binary pushes cold-start execution times below one second. Managed entirely via asynchronous Rust control planes, the resulting architecture ensures that every Imp test iteration executes in a pristine, observable, and fully featured Linux environment with zero inter-test state leakage.

#### **Works cited**

1. Why would you use a microVM (Firecracker, Docker sandbox, nono, etc...) for sandboxing instead of just a Docker container? \- Reddit, [https://www.reddit.com/r/AI\_Agents/comments/1rpblox/why\_would\_you\_use\_a\_microvm\_firecracker\_docker/](https://www.reddit.com/r/AI_Agents/comments/1rpblox/why_would_you_use_a_microvm_firecracker_docker/)
2. I am breaking my head in Analyzing Container Filesystem Isolation For Multi-Tenant Workloads, so you don't have to | by Evangelos Pappas | System Weakness, [https://systemweakness.com/i-am-breaking-my-head-in-analyzing-container-filesystem-isolation-for-multi-tenant-workloads-so-f4982a44d81f](https://systemweakness.com/i-am-breaking-my-head-in-analyzing-container-filesystem-isolation-for-multi-tenant-workloads-so-f4982a44d81f)
3. What is AWS Firecracker? The microVM technology, explained | Blog \- Northflank, [https://northflank.com/blog/what-is-aws-firecracker](https://northflank.com/blog/what-is-aws-firecracker)
4. What is Firecracker? | Browserbase, [https://www.browserbase.com/blog/what-is-firecracker](https://www.browserbase.com/blog/what-is-firecracker)
5. Your Container Is Not a Sandbox: The State of MicroVM Isolation in 2026, [https://emirb.github.io/blog/microvm-2026/](https://emirb.github.io/blog/microvm-2026/)
6. Guide to Cloud Hypervisor in 2026: Modern VMM for cloud workloads | Blog \- Northflank, [https://northflank.com/blog/guide-to-cloud-hypervisor](https://northflank.com/blog/guide-to-cloud-hypervisor)
7. rust-vmm \- FOSDEM 2026, [https://fosdem.org/2026/events/attachments/WEHLEY-rust-vmm\_evolution\_on\_ecosystem\_and\_monorepo/slides/266719/rust-vmm\_q4zaofh.pdf](https://fosdem.org/2026/events/attachments/WEHLEY-rust-vmm_evolution_on_ecosystem_and_monorepo/slides/266719/rust-vmm_q4zaofh.pdf)
8. Firecracker, [https://firecracker-microvm.github.io/](https://firecracker-microvm.github.io/)
9. Firecracker \- Rust Utilities, [https://rustutils.com/tools/firecracker/](https://rustutils.com/tools/firecracker/)
10. Firecracker vs gVisor: Which isolation technology should you use? | Blog \- Northflank, [https://northflank.com/blog/firecracker-vs-gvisor](https://northflank.com/blog/firecracker-vs-gvisor)
11. Firecracker microVMs on OCI | cloud-infrastructure \- Oracle Blogs, [https://blogs.oracle.com/cloud-infrastructure/firecracker-oci-vm-vs-bm](https://blogs.oracle.com/cloud-infrastructure/firecracker-oci-vm-vs-bm)
12. Scale-Driven Architecture: Lessons from a Hyperscale Multi-Tenant Agent Platform on EKS \- Part 2: Isolation and Storage Trade-offs | AWS Builder Center, [https://builder.aws.com/content/3D2W4njwjbbwOog5cT6jGucKR1Y/scale-driven-architecture-lessons-from-a-hyperscale-multi-tenant-agent-platform-on-eks-part-2-isolation-and-storage-trade-offs](https://builder.aws.com/content/3D2W4njwjbbwOog5cT6jGucKR1Y/scale-driven-architecture-lessons-from-a-hyperscale-multi-tenant-agent-platform-on-eks-part-2-isolation-and-storage-trade-offs)
13. VMM/Sandbox Support \- urunc Documentation, [https://urunc.io/hypervisor-support/](https://urunc.io/hypervisor-support/)
14. \[Update\] I tried nested virtualization which is now available on instances other than bare metal | DevelopersIO, [https://dev.classmethod.jp/en/articles/ec2-nested-virtualization-support-non-bare-metal/](https://dev.classmethod.jp/en/articles/ec2-nested-virtualization-support-non-bare-metal/)
15. Deploy Firecracker MicroVMs on a VPS \- RamNode, [https://ramnode.com/guides/firecracker](https://ramnode.com/guides/firecracker)
16. Cloud Hypervisor vs gVisor | Blog \- Northflank, [https://northflank.com/blog/cloud-hypervisor-vs-gvisor](https://northflank.com/blog/cloud-hypervisor-vs-gvisor)
17. Selecting a hypervisor with strong security and isolation, minimal configuration and maintenance, broad guest compatibility \[closed\] \- Server Fault, [https://serverfault.com/questions/1197772/selecting-a-hypervisor-with-strong-security-and-isolation-minimal-configuration](https://serverfault.com/questions/1197772/selecting-a-hypervisor-with-strong-security-and-isolation-minimal-configuration)
18. How to Use Kata Containers with Docker for Enhanced Isolation \- OneUptime, [https://oneuptime.com/blog/post/2026-02-08-how-to-use-kata-containers-with-docker-for-enhanced-isolation/view](https://oneuptime.com/blog/post/2026-02-08-how-to-use-kata-containers-with-docker-for-enhanced-isolation/view)
19. Firecracker vs Cloud Hypervisor | Blog \- Northflank, [https://northflank.com/blog/firecracker-vs-cloud-hypervisor](https://northflank.com/blog/firecracker-vs-cloud-hypervisor)
20. Cloud Hypervisor documentation \- GitHub Pages, [https://intelkevinputnam.github.io/cloud-hypervisor-docs-HTML/README.html](https://intelkevinputnam.github.io/cloud-hypervisor-docs-HTML/README.html)
21. Cloud Hypervisor \- Run Cloud Virtual Machines Securely and Efficiently, [https://www.cloudhypervisor.org/](https://www.cloudhypervisor.org/)
22. cloud-hypervisor/docs/device\_model.md at main \- GitHub, [https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/device\_model.md](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/device_model.md)
23. How to use virtio-fs — Cloud Hypervisor documentation \- GitHub Pages, [https://intelkevinputnam.github.io/cloud-hypervisor-docs-HTML/docs/fs.html](https://intelkevinputnam.github.io/cloud-hypervisor-docs-HTML/docs/fs.html)
24. Cloud Hypervisor v50.0 Released\!, [https://www.cloudhypervisor.org/blog/cloud-hypervisor-v50.0-released/](https://www.cloudhypervisor.org/blog/cloud-hypervisor-v50.0-released/)
25. Cloud Hypervisor is Awesome \- Blake Smith, [https://blakesmith.me/2026/05/03/cloud-hypervisor-is-awesome.html](https://blakesmith.me/2026/05/03/cloud-hypervisor-is-awesome.html)
26. Cloud Hypervisor API \- GitHub Pages, [https://intelkevinputnam.github.io/cloud-hypervisor-docs-HTML/docs/api.html](https://intelkevinputnam.github.io/cloud-hypervisor-docs-HTML/docs/api.html)
27. cloud-hypervisor/docs/api.md at main \- GitHub, [https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/api.md](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/api.md)
28. cloud-hypervisor-client \- crates.io: Rust Package Registry, [https://crates.io/crates/cloud-hypervisor-client](https://crates.io/crates/cloud-hypervisor-client)
29. Unable to restore a snapshot of vm using virtiofs root · Issue \#6931 \- GitHub, [https://github.com/cloud-hypervisor/cloud-hypervisor/issues/6931](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/6931)
30. firecracker-rs-sdk \- crates.io: Rust Package Registry, [https://crates.io/crates/firecracker-rs-sdk](https://crates.io/crates/firecracker-rs-sdk)
31. firepilot \- Rust \- Docs.rs, [https://docs.rs/firepilot](https://docs.rs/firepilot)
32. herolib\_virt \- Rust \- Docs.rs, [https://docs.rs/herolib-virt](https://docs.rs/herolib-virt)
33. Virtio-fs is amazing\! (plus how I set it up) \- Reddit, [https://www.reddit.com/r/VFIO/comments/i12uyn/virtiofs\_is\_amazing\_plus\_how\_i\_set\_it\_up/](https://www.reddit.com/r/VFIO/comments/i12uyn/virtiofs_is_amazing_plus_how_i_set_it_up/)
34. virtiofs \- shared file system for virtual machines, [https://virtio-fs.gitlab.io/](https://virtio-fs.gitlab.io/)
35. virtiofsd \- crates.io: Rust Package Registry, [https://crates.io/crates/virtiofsd](https://crates.io/crates/virtiofsd)
36. cloud-hypervisor/docs/virtiofs-root.md at main \- GitHub, [https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/virtiofs-root.md](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/virtiofs-root.md)
37. virtio-fs / virtiofsd \- GitLab, [https://gitlab.com/virtio-fs/virtiofsd](https://gitlab.com/virtio-fs/virtiofsd)
38. Sharing files with Virtiofs \- Libvirt, [https://libvirt.org/kbase/virtiofs.html](https://libvirt.org/kbase/virtiofs.html)
39. Proxmox 8.4 \- VIRTIOFS (virtiofs) \- Shared Host folder for Linux and/or Windows Guest VMs, [https://forum.proxmox.com/threads/proxmox-8-4-virtiofs-virtiofs-shared-host-folder-for-linux-and-or-windows-guest-vms.167435/](https://forum.proxmox.com/threads/proxmox-8-4-virtiofs-virtiofs-shared-host-folder-for-linux-and-or-windows-guest-vms.167435/)
40. Issue \#5591 · cloud-hypervisor/cloud-hypervisor \- virtiofs Dax \- GitHub, [https://github.com/cloud-hypervisor/cloud-hypervisor/issues/5591](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/5591)
41. Getting Started with Firecracker | Harry Hodge, [https://harryhodge.co.uk/posts/2024/01/getting-started-with-firecracker/](https://harryhodge.co.uk/posts/2024/01/getting-started-with-firecracker/)
42. Isolation layers \- Docker Docs, [https://docs.docker.com/ai/sandboxes/security/isolation/](https://docs.docker.com/ai/sandboxes/security/isolation/)
43. PolarProxy TLS proxy \- Netresec, [https://www.netresec.com/?page=PolarProxy](https://www.netresec.com/?page=PolarProxy)
44. Introduction to Transparent Proxy | Project X, [https://xtls.github.io/en/document/level-2/transparent\_proxy/transparent\_proxy.html](https://xtls.github.io/en/document/level-2/transparent_proxy/transparent_proxy.html)
45. How to secure the tap interface with nftables \- Unix & Linux Stack Exchange, [https://unix.stackexchange.com/questions/735835/how-to-secure-the-tap-interface-with-nftables](https://unix.stackexchange.com/questions/735835/how-to-secure-the-tap-interface-with-nftables)
46. Performing Network Address Translation (NAT) \- nftables wiki, [https://wiki.nftables.org/wiki-nftables/index.php/Performing\_Network\_Address\_Translation\_(NAT)](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_\(NAT\))
47. GitHub All-Stars \#13: Matchlock \- Your Agent's Bulletproof Cage (With Room Service), [https://virtuslab.com/blog/ai/matchlock-your-agents-bulletproof-cage](https://virtuslab.com/blog/ai/matchlock-your-agents-bulletproof-cage)
48. Connector 3 Configuration Guide \- Proxy \[Cisco Spaces\], [https://www.cisco.com/c/en/us/td/docs/wireless/spaces/connector/config/b\_connector\_30/m\_proxy30.html](https://www.cisco.com/c/en/us/td/docs/wireless/spaces/connector/config/b_connector_30/m_proxy30.html)
49. How we got microVMs booting in under a second \- Depot.dev, [https://depot.dev/blog/optimizing-microvm-boot-times](https://depot.dev/blog/optimizing-microvm-boot-times)
50. aws-samples/sample-multi-tenant-openclaw-on-firecracker: OpenClaw Pool — multi-tenant AI agent platform on AWS EC2 Firecracker microVMs with per-tenant isolation, auto-scaling, and web management console. \- GitHub, [https://github.com/aws-samples/sample-multi-tenant-openclaw-on-firecracker](https://github.com/aws-samples/sample-multi-tenant-openclaw-on-firecracker)
51. YOLO: Speeding up VM and Docker Boot Time by reducing I/O operations \- UPCommons, [https://upcommons.upc.edu/bitstreams/35a0036a-4bec-440f-8170-718f436f5953/download](https://upcommons.upc.edu/bitstreams/35a0036a-4bec-440f-8170-718f436f5953/download)
52. How I Built a Firecracker MicroVM Code Execution Engine in Go (17x Faster Cold Starts) | by Abhishek Dadwal | Medium, [https://medium.com/@abhishekdadwal/building-a-production-grade-code-execution-engine-with-firecracker-microvms-21309dadeec9](https://medium.com/@abhishekdadwal/building-a-production-grade-code-execution-engine-with-firecracker-microvms-21309dadeec9)
53. Section 3: Project directions – CS 161 sections, [https://read.seas.harvard.edu/cs161/2024/sections/section3/](https://read.seas.harvard.edu/cs161/2024/sections/section3/)
54. larksuite/perf-monitor-rs: A cross-platform library to retrieve performance statistics data. \- GitHub, [https://github.com/larksuite/perf-monitor-rs](https://github.com/larksuite/perf-monitor-rs)
55. Crate procfs \- tikv \- Rust, [https://tikv.github.io/doc/procfs/index.html](https://tikv.github.io/doc/procfs/index.html)
56. sysinfo — Rust OS-specific library // Lib.rs, [https://lib.rs/crates/sysinfo](https://lib.rs/crates/sysinfo)
57. How to Monitor KVM Virtual Machines \- Fivenines, [https://fivenines.io/blog/how-to-monitor-kvm-virtual-machines/](https://fivenines.io/blog/how-to-monitor-kvm-virtual-machines/)
58. Nested Virtualization \- Crusoe Support, [https://support.crusoecloud.com/hc/en-us/articles/37184397527835-Nested-Virtualization](https://support.crusoecloud.com/hc/en-us/articles/37184397527835-Nested-Virtualization)
59. Confidential Serverless Computing \- arXiv, [https://arxiv.org/html/2504.21518v2](https://arxiv.org/html/2504.21518v2)
60. AWS EC2 Nested Virtualization: Run KVM & Hyper-V Without Bare Metal \- sjramblings.io, [https://sjramblings.io/aws-ec2-nested-virtualization-finally/](https://sjramblings.io/aws-ec2-nested-virtualization-finally/)
61. v50.0 · cloud-hypervisor cloud-hypervisor · Discussion \#7573 \- GitHub, [https://github.com/cloud-hypervisor/cloud-hypervisor/discussions/7573](https://github.com/cloud-hypervisor/cloud-hypervisor/discussions/7573)
62. firecracker/docs/dev-machine-setup.md at main \- GitHub, [https://github.com/firecracker-microvm/firecracker/blob/main/docs/dev-machine-setup.md](https://github.com/firecracker-microvm/firecracker/blob/main/docs/dev-machine-setup.md)
