# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57335");
  script_cve_id("CVE-2005-3352", "CVE-2006-3918");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1167)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1167");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1167");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache' package(s) announced via the DSA-1167 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Apache, the worlds most popular webserver, which may lead to the execution of arbitrary web script. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-3352

A cross-site scripting (XSS) flaw exists in the mod_imap component of the Apache server.

CVE-2006-3918

Apache does not sanitize the Expect header from an HTTP request when it is reflected back in an error message, which might allow cross-site scripting (XSS) style attacks.

For the stable distribution (sarge) these problems have been fixed in version 1.3.33-6sarge3.

For the unstable distribution (sid) these problems have been fixed in version 1.3.34-3.

We recommend that you upgrade your apache package.");

  script_tag(name:"affected", value:"'apache' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);