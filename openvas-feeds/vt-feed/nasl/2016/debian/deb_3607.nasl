# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703607");
  script_cve_id("CVE-2015-7515", "CVE-2016-0821", "CVE-2016-1237", "CVE-2016-1583", "CVE-2016-2117", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2187", "CVE-2016-3070", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3672", "CVE-2016-3951", "CVE-2016-3955", "CVE-2016-3961", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4581", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5243", "CVE-2016-5244");
  script_tag(name:"creation_date", value:"2016-06-27 22:00:00 +0000 (Mon, 27 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 20:31:00 +0000 (Thu, 03 Nov 2022)");

  script_name("Debian: Security Advisory (DSA-3607)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3607");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3607");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3607 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2015-7515, CVE-2016-2184, CVE-2016-2185, CVE-2016-2186, CVE-2016-2187, CVE-2016-3136, CVE-2016-3137, CVE-2016-3138, CVE-2016-3140 Ralf Spenneberg of OpenSource Security reported that various USB drivers do not sufficiently validate USB descriptors. This allowed a physically present user with a specially designed USB device to cause a denial of service (crash).

CVE-2016-0821

Solar Designer noted that the list poisoning feature, intended to mitigate the effects of bugs in list manipulation in the kernel, used poison values within the range of virtual addresses that can be allocated by user processes.

CVE-2016-1237

David Sinquin discovered that nfsd does not check permissions when setting ACLs, allowing users to grant themselves permissions to a file by setting the ACL.

CVE-2016-1583

Jann Horn of Google Project Zero reported that the eCryptfs filesystem could be used together with the proc filesystem to cause a kernel stack overflow. If the ecryptfs-utils package is installed, local users could exploit this, via the mount.ecryptfs_private program, for denial of service (crash) or possibly for privilege escalation.

CVE-2016-2117

Justin Yackoski of Cryptonite discovered that the Atheros L2 ethernet driver incorrectly enables scatter/gather I/O. A remote attacker could take advantage of this flaw to obtain potentially sensitive information from kernel memory.

CVE-2016-2143

Marcin Koscielnicki discovered that the fork implementation in the Linux kernel on s390 platforms mishandles the case of four page-table levels, which allows local users to cause a denial of service (system crash).

CVE-2016-3070

Jan Stancek of Red Hat discovered a local denial of service vulnerability in AIO handling.

CVE-2016-3134

The Google Project Zero team found that the netfilter subsystem does not sufficiently validate filter table entries. A user with the CAP_NET_ADMIN capability could use this for denial of service (crash) or possibly for privilege escalation. Debian disables unprivileged user namespaces by default, if locally enabled with the kernel.unprivileged_userns_clone sysctl, this allows privilege escalation.

CVE-2016-3156

Solar Designer discovered that the IPv4 implementation in the Linux kernel did not perform the destruction of inet device objects properly. An attacker in a guest OS could use this to cause a denial of service (networking outage) in the host OS.

CVE-2016-3157 / XSA-171 Andy Lutomirski discovered that the x86_64 (amd64) task switching implementation did not correctly update the I/O permission level when running as a Xen paravirtual (PV) guest. In some configurations this would allow local users to cause a denial of service (crash) or to escalate their privileges within the guest.

CVE-2016-3672

Hector Marco ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);