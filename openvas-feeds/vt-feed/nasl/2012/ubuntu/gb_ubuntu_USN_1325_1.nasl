# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840860");
  script_cve_id("CVE-2011-1162", "CVE-2011-2203", "CVE-2011-3353", "CVE-2011-3359", "CVE-2011-4110");
  script_tag(name:"creation_date", value:"2012-01-13 05:19:09 +0000 (Fri, 13 Jan 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 23:43:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1325-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1325-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1325-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Huewe discovered an information leak in the handling of reading
security-related TPM data. A local, unprivileged user could read the
results of a previous TPM command. (CVE-2011-1162)

Clement Lecigne discovered a bug in the HFS filesystem. A local attacker
could exploit this to cause a kernel oops. (CVE-2011-2203)

Han-Wen Nienhuys reported a flaw in the FUSE kernel module. A local user
who can mount a FUSE file system could cause a denial of service.
(CVE-2011-3353)

A flaw was found in the b43 driver in the Linux kernel. An attacker could
use this flaw to cause a denial of service if the system has an active
wireless interface using the b43 driver. (CVE-2011-3359)

A flaw was found in how the Linux kernel handles user-defined key types. An
unprivileged local user could exploit this to crash the system.
(CVE-2011-4110)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
