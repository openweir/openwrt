# Sourced by the package install tests, on the runner and inside the router container.

# retry COMMAND...: run a download again after a failure, four attempts in all, 10, 20 and 40 s
# apart. Only fetches (image pulls, package indexes, release assets) go through it, never a test
# step, whose failure is the result. errexit does not apply inside a function run through it,
# so a function must return its own failures.
retry() {
 _retry_attempt=1 _retry_delay=10
 while :; do
  "$@" && return 0
  _retry_status=$?
  if [ "$_retry_attempt" -ge 4 ]; then
   echo "Failed $_retry_attempt times: $*" >&2
   return "$_retry_status"
  fi
  echo "Attempt $_retry_attempt failed (status $_retry_status), retrying in ${_retry_delay}s: $*" >&2
  sleep "$_retry_delay"
  _retry_attempt=$((_retry_attempt + 1)) _retry_delay=$((_retry_delay * 2))
 done
}

# bounded SECONDS COMMAND...: fail a command that hangs instead of holding the runner until the
# job times out. Without GNU timeout (some developer machines) the command runs unbounded.
bounded() {
 _bounded_limit=$1; shift
 command -v timeout >/dev/null 2>&1 || { "$@"; return; }
 _bounded_status=0
 timeout -k 30 "$_bounded_limit" "$@" || _bounded_status=$?
 [ "$_bounded_status" != 124 ] || echo "Timed out after ${_bounded_limit}s: $*" >&2
 return "$_bounded_status"
}
