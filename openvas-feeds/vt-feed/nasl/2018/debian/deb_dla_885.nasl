# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890885");
  script_cve_id("CVE-2017-7233", "CVE-2017-7234");
  script_tag(name:"creation_date", value:"2018-01-16 23:00:00 +0000 (Tue, 16 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-885)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-885");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-885");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DLA-885 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were two vulnerabilities in python-django, a high-level Python web development framework.

CVE-2017-7233 (#859515) Open redirect and possible XSS attack via user-supplied numeric redirect URLs. Django relies on user input in some cases (e.g. django.contrib.auth.views.login() and i18n) to redirect the user to an on success URL. The security check for these redirects (namely is_safe_url()) considered some numeric URLs (e.g. http:999999999) safe when they shouldn't be. Also, if a developer relied on is_safe_url() to provide safe redirect targets and puts such a URL into a link, they could suffer from an XSS attack.

CVE-2017-7234 (#895516) Open redirect vulnerability in django.views.static.serve, A maliciously crafted URL to a Django site using the serve() view could redirect to any other domain. The view no longer does any redirects as they don't provide any known, useful functionality.

For Debian 7 Wheezy, this issue has been fixed in python-django version 1.4.22-1+deb7u3.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);