#!/usr/bin/env Rscript
# score_summarize.R — Rscript process B of the mandatory two-process pattern.
#
# Reads the RDS produced by score_assess.R (process A), scores it with
# pkg_score(), computes the overall score with summarize_scores(), and writes
# a JSON result file (never relies on stdout for results).
#
# Output JSON fields:
#   overall_score, metric_scores (named 0-1 risks), metric_raw (printable raw
#   values where available), excluded_metrics (code-executing, forced NA),
#   r_version, riskmetric_version, assessed_at (UTC).
#
# Usage: Rscript --vanilla score_summarize.R <in_rds_path> <out_json_path>

`%||%` <- function(a, b) if (is.null(a)) b else a

args <- commandArgs(trailingOnly = TRUE)
if (length(args) < 2) {
  stop("usage: score_summarize.R <in_rds_path> <out_json_path>")
}
in_rds <- args[[1]]
out_json <- args[[2]]

cat("[score_summarize] loading riskmetric\n")
suppressPackageStartupMessages(library(riskmetric))
suppressPackageStartupMessages(library(jsonlite))

assessed <- readRDS(in_rds)
cat("[score_summarize] loaded assessments from", in_rds, "\n")

excluded <- c("assess_covr_coverage", "assess_r_cmd_check")
if (any(excluded %in% names(assessed))) {
  stop("SECURITY VIOLATION: code-executing metric present in assessment input")
}

cat("[score_summarize] scoring\n")
scored <- pkg_score(assessed)
overall <- as.numeric(summarize_scores(scored))
cat("[score_summarize] overall score:", overall, "\n")

# assessment columns are "assess_*"; scored columns drop the "assess_" prefix
assess_cols <- setdiff(names(assessed), c("package", "version"))
metric_scores <- list()
metric_raw <- list()
for (acol in assess_cols) {
  m <- sub("^assess_", "", acol)
  val <- if (m %in% names(scored)) scored[[m]] else NA
  # pkg_score output columns carry the numeric 0-1 risk; NA when not scored
  if (is.numeric(val) && length(val) == 1 && !is.na(val)) {
    metric_scores[[m]] <- as.numeric(val)
  } else {
    metric_scores[[m]] <- NA
  }
  raw <- assessed[[acol]]
  # printable raw values only (skip complex objects like pkg_metric_error)
  if (inherits(raw, "pkg_metric_error")) {
    metric_raw[[m]] <- paste0("[assessment error: ",
                              conditionMessage(attr(raw, "error") %||%
                                                 simpleError("unknown")), "]")
  } else if (is.atomic(raw) && length(raw) == 1) {
    metric_raw[[m]] <- as.character(raw)
  } else {
    metric_raw[[m]] <- NA_character_
  }
}

result <- list(
  overall_score = ifelse(is.na(overall), NA, overall),
  metric_scores = metric_scores,
  metric_raw = metric_raw,
  excluded_metrics = excluded,
  security_note = paste(
    "code-executing metrics excluded; assessed package code was not executed"),
  r_version = R.version.string,
  riskmetric_version = as.character(packageVersion("riskmetric")),
  assessed_at = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
)

writeLines(toJSON(result, auto_unbox = TRUE, na = "null", pretty = TRUE),
           out_json)
cat("[score_summarize] wrote JSON to", out_json, "\n")
cat("[score_summarize] DONE\n")
