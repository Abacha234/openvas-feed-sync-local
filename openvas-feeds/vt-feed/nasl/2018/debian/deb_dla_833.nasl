# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890833");
  script_cve_id("CVE-2014-9888", "CVE-2014-9895", "CVE-2016-6786", "CVE-2016-6787", "CVE-2016-8405", "CVE-2017-5549", "CVE-2017-6001", "CVE-2017-6074");
  script_tag(name:"creation_date", value:"2018-01-07 23:00:00 +0000 (Sun, 07 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-10 00:53:00 +0000 (Fri, 10 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-833)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-833");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-833");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-833 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or have other impacts.

CVE-2014-9888

Russell King found that on ARM systems, memory allocated for DMA buffers was mapped with executable permission. This made it easier to exploit other vulnerabilities in the kernel.

CVE-2014-9895

Dan Carpenter found that the MEDIA_IOC_ENUM_LINKS ioctl on media devices resulted in an information leak.

CVE-2016-6786 / CVE-2016-6787 It was discovered that the performance events subsystem does not properly manage locks during certain migrations, allowing a local attacker to escalate privileges. This can be mitigated by disabling unprivileged use of performance events: sysctl kernel.perf_event_paranoid=3

CVE-2016-8405

Peter Pi of Trend Micro discovered that the frame buffer video subsystem does not properly check bounds while copying color maps to userspace, causing a heap buffer out-of-bounds read, leading to information disclosure.

CVE-2017-5549

It was discovered that the KLSI KL5KUSB105 serial USB device driver could log the contents of uninitialised kernel memory, resulting in an information leak.

CVE-2017-6001

Di Shen discovered a race condition between concurrent calls to the performance events subsystem, allowing a local attacker to escalate privileges. This flaw exists because of an incomplete fix of CVE-2016-6786. This can be mitigated by disabling unprivileged use of performance events: sysctl kernel.perf_event_paranoid=3

CVE-2017-6074

Andrey Konovalov discovered a use-after-free vulnerability in the DCCP networking code, which could result in denial of service or local privilege escalation. On systems that do not already have the dccp module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-dccp.conf install dccp false

For Debian 7 Wheezy, these problems have been fixed in version 3.2.84-2.

For Debian 8 Jessie, these problems have been fixed in version 3.16.39-1+deb8u1 or earlier.

We recommend that you upgrade your linux packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);