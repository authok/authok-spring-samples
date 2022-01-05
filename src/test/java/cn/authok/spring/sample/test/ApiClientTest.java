package cn.authok.spring.sample.test;

import cn.authok.spring.sample.models.Contact;
import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.CustomRequest;
import com.fasterxml.jackson.core.type.TypeReference;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;

/**
 * 编程访问 资源服务器
 */
public class ApiClientTest {
    public static void main(String[] args) throws Auth0Exception {
        AuthAPI authApi = new AuthAPI("https://wsz.cn.authok.cn", "_f8riekVm23IjMsIsqEFjdhKH6i7tilr", "gJXi9XSC5AsXu4FAJLi5R1W__TisCIlzDNGhN-P6zA65WPRcvNqdqUuRtkRQdQ5E");

        TokenHolder token = authApi.requestToken("https://wsz.com/api/v1/").execute();
        String apiToken = token.getAccessToken();

        String contactId = "1";

        HttpUrl baseUrl = HttpUrl.parse("http://localhost:8083");
        OkHttpClient client = new OkHttpClient.Builder().build();
        HttpUrl.Builder builder = baseUrl
                .newBuilder()
                .addPathSegments("api/v1/contacts")
                .addPathSegment(contactId);

        String url = builder.build().toString();

        CustomRequest<Contact> request = new CustomRequest<Contact>(client, url, "GET", new TypeReference<Contact>() {
        });

        request.addHeader("Authorization", "Bearer " + apiToken);

        Contact contact = request.execute();
        System.out.printf("r: %s", contact);
    }
}
