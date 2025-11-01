# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856895");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2024-24815");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 15:09:37 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2025-01-08 05:00:06 +0000 (Wed, 08 Jan 2025)");
  script_name("openSUSE: Security Advisory for python (openSUSE-SU-2025:0008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0008-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZXNT2JPQVYWDQRDN2YJ7KJCRBY5QEJQW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the openSUSE-SU-2025:0008-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-django-ckeditor fixes the following issues:

  - Update to 6.7.2

  * Deprecated the package.

  * Added a new ckeditor/fixups.js script which disables the version check
         again (if something slips through by accident) and which disables the
         behavior where CKEditor 4 would automatically attach itself to
         unrelated HTML elements with a contenteditable attribute (see
         CKEDITOR.disableAutoInline in the CKEditor 4 docs).

  - CVE-2024-24815: Fixed bypass of Advanced Content Filtering mechanism
       (boo#1219720)

  - update to 6.7.1:

  * Add Python 3.12, Django 5.0

  * Silence the CKEditor version check/nag but include a system check
         warning

  - update to 6.7.0:

  * Dark mode fixes.

  * Added support for Pillow 10.

  - update to 6.6.1:

  * Required a newer version of django-js-asset which actually works with
         Django 4.1.

  * CKEditor 4.21.0

  * Fixed the CKEditor styles when used with the dark Django admin theme.

  - update to 6.5.1:

  * Avoided calling ``static()`` if ``CKEDITOR_BASEPATH`` is defined.

  * Fixed ``./manage.py generateckeditorthumbnails`` to work again after
         the image uploader backend rework.

  * CKEditor 4.19.1

  * Stopped calling ``static()`` during application startup.

  * Added Django 4.1

  * Changed the context for the widget to deviate less from Django.
         Removed a

  * few template variables which are not used in the bundled

  * ``ckeditor/widget.html`` template. This only affects you if you are
         using a

  * customized widget or widget template.

  * Dropped support for Python   3.8, Django   3.2.

  * Added a pre-commit configuration.

  * Added a GitHub action for running tests.

  * Made selenium tests require opt in using a ``SELENIUM=firefox`` or
         ``SELENIUM=chromium`` environment variable.

  * Made it possible to override the CKEditor template in the widget class.

  * Changed ``CKEDITOR_IMAGE_BACKEND`` to require dotted module paths (the
         old identifiers are still supported for now).");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
