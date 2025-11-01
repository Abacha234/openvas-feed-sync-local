# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128159");
  script_version("2025-10-23T05:39:29+0000");
  script_tag(name:"last_modification", value:"2025-10-23 05:39:29 +0000 (Thu, 23 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-06-20 10:41:19 +0000 (Fri, 20 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-22 18:56:38 +0000 (Fri, 22 Aug 2025)");

  script_cve_id("CVE-2025-49576");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki >= 2.31.0 < 3.3.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS)
  vulnerability.

  Note: This VT has been deprecated as it had targeted the wrong product. It is therefore no longer
  functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The citizen-search-noresults-title and citizen-search-noresults-
  desc system messages are inserted into raw HTML, allowing anybody who can edit those messages to
  insert arbitrary HTML into the DOM.");

  script_tag(name:"affected", value:"MediaWiki version through 2.31.0 prior to 3.3.1.");

  script_tag(name:"solution", value:"Update to version 3.3.1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-86xf-2mgp-gv3g");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# nb: VT is about a "Citizen" 3rd-party MediaWiki Skin which is (at least currently) not remotely
# detected and not about MediaWiki itself.
exit(66);
