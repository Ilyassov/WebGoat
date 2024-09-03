package org.owasp.webgoat.lessons.cryptography;

import jakarta.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"crypto-hashing.hints.1", "crypto-hashing.hints.2"})
public class HashingAssignment extends AssignmentEndpoint {

  public static final String[] SECRETS = {"secret", "admin", "password", "123456", "passw0rd"};

  @RequestMapping(path = "/crypto/hashing/sha384", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSha384(HttpServletRequest request) throws NoSuchAlgorithmException {

    String sha384 = (String) request.getSession().getAttribute("sha384");
    if (sha384 == null) {
      String secret = SECRETS[new Random().nextInt(SECRETS.length)];
      sha384 = getHash(secret, "SHA-384");
      request.getSession().setAttribute("sha384Hash", sha384);
      request.getSession().setAttribute("sha384Secret", secret);
    }
    return sha384;
  }

  @PostMapping("/crypto/hashing")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_pwd1,
      @RequestParam String answer_pwd2) {

    String sha384Secret = (String) request.getSession().getAttribute("sha384Secret");

    if (answer_pwd1 != null && answer_pwd2 != null) {
      if (answer_pwd1.equals(sha384Secret)) {
        return success(this).feedback("crypto-hashing.success").build();
      } else {
        return failed(this).feedback("crypto-hashing.oneok").build();
      }
    }
    return failed(this).feedback("crypto-hashing.empty").build();
  }

  public static String getHash(String secret, String algorithm) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(secret.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest).toUpperCase();
  }
}