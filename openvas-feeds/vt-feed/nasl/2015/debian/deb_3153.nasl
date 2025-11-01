# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703153");
  script_cve_id("CVE-2014-5352", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_tag(name:"creation_date", value:"2015-02-02 23:00:00 +0000 (Mon, 02 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3153");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3153");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-3153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in krb5, the MIT implementation of Kerberos:

CVE-2014-5352

Incorrect memory management in the libgssapi_krb5 library might result in denial of service or the execution of arbitrary code.

CVE-2014-9421

Incorrect memory management in kadmind's processing of XDR data might result in denial of service or the execution of arbitrary code.

CVE-2014-9422

Incorrect processing of two-component server principals might result in impersonation attacks.

CVE-2014-9423

An information leak in the libgssrpc library.

For the stable distribution (wheezy), these problems have been fixed in version 1.10.1+dfsg-5+deb7u3.

For the unstable distribution (sid), these problems have been fixed in version 1.12.1+dfsg-17.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);