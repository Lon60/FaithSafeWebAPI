package com.faithsafe.api.download;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/download")
public class DownloadController {

  byte[] empty = new byte[0];

  @Operation(description = """
      # Info
      .exe file download.\s
      ## Security
      This endpoint does require the **USER** Role or above.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
  @GetMapping("/exe")
  public ResponseEntity<ByteArrayResource> downloadExe() {
    ByteArrayResource resource = new ByteArrayResource(empty);

    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=faithsafe.exe");
    headers.add(HttpHeaders.CONTENT_TYPE, "application/octet-stream");

    return ResponseEntity.ok()
        .headers(headers)
        .contentLength(empty.length)
        .body(resource);
  }

  @Operation(description = """
      # Info
      .exe file download.\s
      ## Security
      This endpoint does require the **USER** Role or above.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
  @GetMapping("/msi")
  public ResponseEntity<ByteArrayResource> downloadMsi() {
    ByteArrayResource resource = new ByteArrayResource(empty);

    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=faithsafe.msi");
    headers.add(HttpHeaders.CONTENT_TYPE, "application/octet-stream");

    return ResponseEntity.ok()
        .headers(headers)
        .contentLength(empty.length)
        .body(resource);
  }

  @Operation(description = """
      # Info
      .exe file download.\s
      ## Security
      This endpoint does require the **USER** Role or above.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
  @GetMapping("/app")
  public ResponseEntity<ByteArrayResource> downloadMacApp() {
    ByteArrayResource resource = new ByteArrayResource(empty);

    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=faithsafe.app");
    headers.add(HttpHeaders.CONTENT_TYPE, "application/octet-stream");

    return ResponseEntity.ok()
        .headers(headers)
        .contentLength(empty.length)
        .body(resource);
  }
}
