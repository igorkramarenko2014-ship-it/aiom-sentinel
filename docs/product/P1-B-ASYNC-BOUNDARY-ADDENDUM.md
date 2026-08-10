# P1-B async boundary addendum

Future scan commands will be asynchronous, accept owned versioned DTOs, and return serializable `ApplicationErrorV1` values. Heavy scanning work must remain off the UI thread. The foundation exposes only `get_product_status_v1`; scan commands are intentionally out of scope.
