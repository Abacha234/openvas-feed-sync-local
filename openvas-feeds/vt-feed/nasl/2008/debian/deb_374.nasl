# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53696");
  script_cve_id("CVE-2003-0686");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-374");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-374");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpam-smb' package(s) announced via the DSA-374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libpam-smb is a PAM authentication module which makes it possible to authenticate users against a password database managed by Samba or a Microsoft Windows server. If a long password is supplied, this can cause a buffer overflow which could be exploited to execute arbitrary code with the privileges of the process which invokes PAM services.

For the stable distribution (woody) this problem has been fixed in version 1.1.6-1.1woody1.

The unstable distribution (sid) does not contain a libpam-smb package.

We recommend that you update your libpam-smb package.");

  script_tag(name:"affected", value:"'libpam-smb' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);