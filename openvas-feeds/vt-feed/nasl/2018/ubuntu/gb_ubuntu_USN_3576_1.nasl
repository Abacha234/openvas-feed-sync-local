# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843454");
  script_cve_id("CVE-2016-5008", "CVE-2017-1000256", "CVE-2018-5748", "CVE-2018-6764");
  script_tag(name:"creation_date", value:"2018-02-21 07:47:28 +0000 (Wed, 21 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-3576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3576-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3576-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-3576-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vivian Zhang and Christoph Anton Mitterer discovered that libvirt
incorrectly disabled password authentication when the VNC password was set
to an empty string. A remote attacker could possibly use this issue to
bypass authentication, contrary to expectations. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-5008)

Daniel P. Berrange discovered that libvirt incorrectly handled validating
SSL/TLS certificates. A remote attacker could possibly use this issue to
obtain sensitive information. This issue only affected Ubuntu 17.10.
(CVE-2017-1000256)

Daniel P. Berrange and Peter Krempa discovered that libvirt incorrectly
handled large QEMU replies. An attacker could possibly use this issue to
cause libvirt to crash, resulting in a denial of service. (CVE-2018-5748)

Pedro Sampaio discovered that libvirt incorrectly handled the libnss_dns.so
module. An attacker in a libvirt_lxc session could possibly use this issue
to execute arbitrary code. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 17.10. (CVE-2018-6764)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
