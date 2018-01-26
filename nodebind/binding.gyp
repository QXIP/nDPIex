{
  "targets": [
    {
      "target_name": "ndpiex",
      "sources": [
        "ndpiexlib.c",
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "/usr/local/include/libndpi-1.8.0/libndpi/"
      ]
    }
  ]
}
