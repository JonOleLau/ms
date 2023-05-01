import java.io.*;

class CustomObject implements Serializable {
    private static final long serialVersionUID = 1L;

    private String value;

    public CustomObject(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "CustomObject{" +
                "value='" + value + '\'' +
                '}';
    }
}

public class Remote_code {

    public static void main(String[] args) throws IOException, ClassNotFoundException {

        // Serialize a sample CustomObject
        CustomObject customObj = new CustomObject("sample value");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(customObj);
        oos.close();

        String serializedObj = new String(baos.toByteArray());

        // Vulnerable code 1 - Deserialization of untrusted data
        ObjectInputStream objInStream = new ObjectInputStream(new ByteArrayInputStream(serializedObj.getBytes()));
        Object obj = objInStream.readObject();
        System.out.println("Deserialized object: " + obj.toString());

        // Vulnerable code 2 - Dynamic code execution using Runtime.exec()
        String command = "cmd.exe /c echo Vulnerable code executed successfully.";
        Runtime.getRuntime().exec(command);
        System.out.println("Command executed successfully.");

        // Vulnerable code 3 - Reflection-based code execution
        String className = "java.util.ArrayList";
        try {
            Class cls = Class.forName(className);
            Object obj2 = cls.newInstance();
            System.out.println("Object created: " + obj2.toString());
        } catch (ClassNotFoundException ex) {
            System.out.println("Class not found: " + ex.getMessage());
        } catch (InstantiationException ex) {
            System.out.println("Error creating object: " + ex.getMessage());
        } catch (IllegalAccessException ex) {
            System.out.println("Error creating object: " + ex.getMessage());
        }
    }
}
