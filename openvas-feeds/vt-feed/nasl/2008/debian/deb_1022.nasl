# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56528");
  script_cve_id("CVE-2005-3146", "CVE-2005-3147", "CVE-2005-3148");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1022");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1022");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'storebackup' package(s) announced via the DSA-1022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the backup utility storebackup. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-3146

Storebackup creates a temporary file predictably, which can be exploited to overwrite arbitrary files on the system with a symlink attack.

CVE-2005-3147

The backup root directory wasn't created with fixed permissions, which may lead to improper permissions if the umask is too lax.

CVE-2005-3148

The user and group rights of symlinks are set incorrectly when making or restoring a backup, which may leak sensitive data.

The old stable distribution (woody) doesn't contain storebackup packages.

For the stable distribution (sarge) these problems have been fixed in version 1.18.4-2sarge1.

For the unstable distribution (sid) these problems have been fixed in version 1.19-2.

We recommend that you upgrade your storebackup package.");

  script_tag(name:"affected", value:"'storebackup' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);