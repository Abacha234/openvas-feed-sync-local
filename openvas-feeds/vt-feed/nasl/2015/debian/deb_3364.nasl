# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703364");
  script_cve_id("CVE-2015-5156", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-8215");
  script_tag(name:"creation_date", value:"2015-09-20 22:00:00 +0000 (Sun, 20 Sep 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3364");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3364");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation or denial of service.

CVE-2015-8215

It was discovered that NetworkManager would set IPv6 MTUs based on the values received in IPv6 RAs (Router Advertisements), without sufficiently validating these values. A remote attacker could exploit this attack to disable IPv6 connectivity. This has been mitigated by adding validation in the kernel.

CVE-2015-2925

Jann Horn discovered that when a subdirectory of a filesystem is bind-mounted into a container that has its own user and mount namespaces, a process with CAP_SYS_ADMIN capability in the user namespace can access files outside of the subdirectory. The default Debian configuration mitigated this as it does not allow unprivileged users to create new user namespaces.

CVE-2015-5156

Jason Wang discovered that when a virtio_net device is connected to a bridge in the same VM, a series of TCP packets forwarded through the bridge may cause a heap buffer overflow. A remote attacker could use this to cause a denial of service (crash) or possibly for privilege escalation.

CVE-2015-6252

Michael S. Tsirkin of Red Hat Engineering found that the vhost driver leaked file descriptors passed to it with the VHOST_SET_LOG_FD ioctl command. A privileged local user with access to the /dev/vhost-net file, either directly or via libvirt, could use this to cause a denial of service (hang or crash).

CVE-2015-6937

It was found that the Reliable Datagram Sockets (RDS) protocol implementation did not verify that an underlying transport exists when creating a connection. Depending on how a local RDS application initialised its sockets, a remote attacker might be able to cause a denial of service (crash) by sending a crafted packet.

CVE-2015-7312

Xavier Chantry discovered that the patch provided by the aufs project to correct behaviour of memory-mapped files from an aufs mount introduced a race condition in the msync() system call. Ben Hutchings found that it also introduced a similar bug in the madvise_remove() function. A local attacker could use this to cause a denial of service or possibly for privilege escalation.

For the oldstable distribution (wheezy), these problems have been fixed in version 3.2.68-1+deb7u4. CVE-2015-2925 and CVE-2015-7312 do not affect the wheezy distribution.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt11-1+deb8u4.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);