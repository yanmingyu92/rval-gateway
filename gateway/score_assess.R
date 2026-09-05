#!/usr/bin/env Rscript
# score_assess.R — Rscript process A of the mandatory two-process pattern.
#
# Known flakiness: running pkg_assess() (network) and pkg_score() in one
# Rscript process intermittently segfaults. This process ONLY assesses and
# serializes; scoring happens in a separate process (score_summarize.R).
#
# SECURITY: the assessed package's code is NEVER executed. The code-executing
# metrics assess_covr_coverage and assess_r_cmd_check (they run tests/checks
# on source refs) are explicitly excluded from the assessment list, and their
# absence from the assessment output is verified before saving.
#
# Usage: Rscript --vanilla score_assess.R <tarball_path> <out_rds_path>
# Writes results to a file (never stdout). Progress markers via cat().

args <- commandArgs(trailingOnly = TRUE)
if (length(args) < 2) {
  stop("usage: score_assess.R <tarball_path> <out_rds_path>")
}
tarball_path <- normalizePath(args[[1]], winslash = "/", mustWork = TRUE)
out_rds <- args[[2]]

cat("[score_assess] loading riskmetric\n")
suppressPackageStartupMessages(library(riskmetric))
cat("[score_assess] riskmetric", as.character(packageVersion("riskmetric")),
    "on", R.version.string, "\n")

cat("[score_assess] building pkg_source ref for", tarball_path, "\n")
# pkg_source refs require an extracted source directory (dir.exists check
# inside riskmetric); untar to a per-run tempdir and ref the package root.
extract_dir <- tempfile("rval_src_")
dir.create(extract_dir, recursive = TRUE)
utils::untar(tarball_path, exdir = extract_dir)
pkg_dirs <- list.dirs(extract_dir, recursive = FALSE)
desc_dirs <- pkg_dirs[file.exists(file.path(pkg_dirs, "DESCRIPTION"))]
if (length(desc_dirs) != 1) {
  stop("cannot locate package source root (DESCRIPTION) in extracted tarball")
}
cat("[score_assess] extracted source at", desc_dirs[[1]], "\n")
ref <- pkg_ref(desc_dirs[[1]], source = "pkg_source")
if (inherits(ref, "pkg_missing")) {
  stop("riskmetric could not build a pkg_source ref (ref class: pkg_missing)")
}

# Explicit assessment list: all metrics EXCEPT the code-executing ones.
all_a <- all_assessments()
excluded <- c("assess_covr_coverage", "assess_r_cmd_check")
keep <- all_a[!names(all_a) %in% excluded]
cat("[score_assess] assessing", length(keep), "metrics; excluded:",
    paste(excluded, collapse = ", "), "\n")

assessed <- pkg_assess(ref, assessments = keep)

# Security verification: excluded metrics must not appear in the output.
present <- names(assessed)
if (any(excluded %in% present)) {
  stop("SECURITY VIOLATION: code-executing metric present in assessment output")
}
cat("[score_assess] verified: no code-executing metrics in output\n")

saveRDS(assessed, out_rds)
cat("[score_assess] saved assessments to", out_rds, "\n")
cat("[score_assess] DONE\n")
