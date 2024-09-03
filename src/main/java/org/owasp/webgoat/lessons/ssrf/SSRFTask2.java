package org.owasp.webgoat.lessons.ssrf;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 extends AssignmentEndpoint {

  private static final Map<String, String> lookupTable = new HashMap<>();
  static {
    lookupTable.put("ifconfig", "http://ifconfig.pro");
  }

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String key) {
    return furBall(key);
  }

  protected AttackResult furBall(String key) {
    String url = lookupTable.get(key);
    if (url != null) {
      String html;
      try (InputStream in = new URL(url).openStream()) {
        html = new String(in.readAllBytes(), StandardCharsets.UTF_8)
            .replaceAll("\n", "<br>");
      } catch (IOException e) {
        html = "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve"
            + " this exercise the right way!</body></html>";
      }
      return success(this).feedback("ssrf.success").output(html).build();
    }
    var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
    return getFailedResult(html);
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}