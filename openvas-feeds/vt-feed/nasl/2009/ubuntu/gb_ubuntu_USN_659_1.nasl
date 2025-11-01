# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840224");
  script_cve_id("CVE-2007-6716", "CVE-2008-2372", "CVE-2008-3276", "CVE-2008-3525", "CVE-2008-3526", "CVE-2008-3534", "CVE-2008-3535", "CVE-2008-3792", "CVE-2008-3831", "CVE-2008-3915", "CVE-2008-4113", "CVE-2008-4445");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:40:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-659-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-659-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-659-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15, linux-source-2.6.22' package(s) announced via the USN-659-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the direct-IO subsystem did not correctly validate
certain structures. A local attacker could exploit this to cause a system
crash, leading to a denial of service. (CVE-2007-6716)

It was discovered that the disabling of the ZERO_PAGE optimization could
lead to large memory consumption. A local attacker could exploit this to
allocate all available memory, leading to a denial of service.
(CVE-2008-2372)

It was discovered that the Datagram Congestion Control Protocol (DCCP) did
not correctly validate its arguments. If DCCP was in use, a remote attacker
could send specially crafted network traffic and cause a system crash,
leading to a denial of service. (CVE-2008-3276)

It was discovered that the SBNI WAN driver did not correctly check for the
NET_ADMIN capability. A malicious local root user lacking CAP_NET_ADMIN
would be able to change the WAN device configuration, leading to a denial
of service. (CVE-2008-3525)

It was discovered that the Stream Control Transmission Protocol (SCTP) did
not correctly validate the key length in the SCTP_AUTH_KEY option. If SCTP
is in use, a remote attacker could send specially crafted network traffic
that would crash the system, leading to a denial of service.
(CVE-2008-3526)

It was discovered that the tmpfs implementation did not correctly handle
certain sequences of inode operations. A local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2008-3534)

It was discovered that the readv/writev functions did not correctly handle
certain sequences of file operations. A local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2008-3535)

It was discovered that SCTP did not correctly validate its userspace
arguments. A local attacker could call certain sctp_* functions with
malicious options and cause a system crash, leading to a denial of service.
(CVE-2008-3792, CVE-2008-4113, CVE-2008-4445)

It was discovered the i915 video driver did not correctly validate
memory addresses. A local attacker could exploit this to remap memory
that could cause a system crash, leading to a denial of service.
(CVE-2008-3831)

Johann Dahm and David Richter discovered that NFSv4 did not correctly
handle certain file ACLs. If NFSv4 is in use, a local attacker could create
a malicious ACL that could cause a system crash, leading to a denial of
service. (CVE-2008-3915)");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.15, linux-source-2.6.22' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
