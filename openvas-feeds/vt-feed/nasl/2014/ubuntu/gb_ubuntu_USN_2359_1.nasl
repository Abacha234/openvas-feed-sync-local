# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841976");
  script_cve_id("CVE-2014-3601", "CVE-2014-5077", "CVE-2014-5471", "CVE-2014-5472");
  script_tag(name:"creation_date", value:"2014-09-24 04:02:50 +0000 (Wed, 24 Sep 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2359-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2359-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2359-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2359-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jack Morgenstein reported a flaw in the page handling of the KVM (Kernel
Virtual Machine) subsystem in the Linux kernel. A guest OS user could
exploit this flaw to cause a denial of service (host OS memory corruption)
or possibly have other unspecified impact on the host OS. (CVE-2014-3601)

Jason Gunthorpe reported a flaw with SCTP authentication in the Linux
kernel. A remote attacker could exploit this flaw to cause a denial of
service (NULL pointer dereference and OOPS). (CVE-2014-5077)

Chris Evans reported an flaw in the Linux kernel's handling of iso9660
(compact disk filesystem) images. An attacker who can mount a custom
iso9660 image either via a CD/DVD drive or a loopback mount could cause a
denial of service (system crash or reboot). (CVE-2014-5471)

Chris Evans reported an flaw in the Linux kernel's handling of iso9660
(compact disk filesystem) images. An attacker who can mount a custom
iso9660 image, with a self-referential CL entry, either via a CD/DVD drive
or a loopback mount could cause a denial of service (unkillable mount
process). (CVE-2014-5472)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
