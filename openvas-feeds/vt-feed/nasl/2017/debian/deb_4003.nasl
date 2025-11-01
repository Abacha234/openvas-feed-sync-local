# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704003");
  script_cve_id("CVE-2017-1000256");
  script_tag(name:"creation_date", value:"2017-10-18 22:00:00 +0000 (Wed, 18 Oct 2017)");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-4003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4003");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4003");
  script_xref(name:"URL", value:"https://security.libvirt.org/2017/0002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvirt' package(s) announced via the DSA-4003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel P. Berrange reported that Libvirt, a virtualisation abstraction library, does not properly handle the default_tls_x509_verify (and related) parameters in qemu.conf when setting up TLS clients and servers in QEMU, resulting in TLS clients for character devices and disk devices having verification turned off and ignoring any errors while validating the server certificate.

More information in [link moved to references].

For the stable distribution (stretch), this problem has been fixed in version 3.0.0-4+deb9u1.

For the unstable distribution (sid), this problem has been fixed in version 3.8.0-3.

We recommend that you upgrade your libvirt packages.");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);