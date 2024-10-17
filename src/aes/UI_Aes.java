package aes;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JTextArea;
import javax.swing.border.TitledBorder;
import javax.swing.border.BevelBorder;
import java.awt.Color;
import javax.swing.JScrollPane;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.Point;
import javax.swing.ScrollPaneConstants;
import java.awt.Insets;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.Toolkit;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class UI_Aes extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private JTextField txtKey;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					UI_Aes frame = new UI_Aes();
					frame.setTitle("AES MÃ HÓA/GIẢI MÃ");
					frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
					frame.setLocationRelativeTo(null);
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public UI_Aes() {
		setIconImage(Toolkit.getDefaultToolkit().getImage(UI_Aes.class.getResource("/img/security_aes_3688.png")));
		setResizable(false);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 850, 690);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));

		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new BevelBorder(BevelBorder.RAISED, null, null, null, null), "Input", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel.setBounds(10, 10, 816, 200);
		contentPane.add(panel);
		panel.setLayout(null);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setFont(new Font("Dialog", Font.PLAIN, 13));
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		scrollPane.setBounds(10, 23, 796, 167);
		panel.add(scrollPane);
		
		JTextArea txtInput = new JTextArea();
		txtInput.setMargin(new Insets(2, 5, 2, 5));
		txtInput.setFont(new Font("Dialog", Font.PLAIN, 16));
		txtInput.setLineWrap(true);
		scrollPane.setViewportView(txtInput);
		
		JPanel panel1 = new JPanel();
		panel1.setLayout(null);
		panel1.setBorder(new TitledBorder(new BevelBorder(BevelBorder.RAISED, null, null, null, null), "Key lenght (bits)", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel1.setBounds(10, 220, 816, 76);
		contentPane.add(panel1);
		
		JComboBox cmbKeyLenght = new JComboBox();
		cmbKeyLenght.setModel(new DefaultComboBoxModel(new String[] {"128 bits", "192 bits", "256 bits"}));
		cmbKeyLenght.setFont(new Font("Dialog", Font.PLAIN, 16));
		cmbKeyLenght.setBounds(10, 23, 796, 43);
		panel1.add(cmbKeyLenght);
		
		JPanel panel2 = new JPanel();
		panel2.setLayout(null);
		panel2.setBorder(new TitledBorder(new BevelBorder(BevelBorder.RAISED, null, null, null, null), "Key", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel2.setBounds(10, 306, 816, 76);
		contentPane.add(panel2);
		
		txtKey = new JTextField();
		txtKey.setMargin(new Insets(2, 4, 2, 2));
		txtKey.setFont(new Font("Dialog", Font.PLAIN, 16));
		txtKey.setBounds(10, 23, 796, 43);
		panel2.add(txtKey);
		txtKey.setColumns(10);
		
		JPanel panel3 = new JPanel();
		panel3.setLayout(null);
		panel3.setBorder(new TitledBorder(new BevelBorder(BevelBorder.RAISED, null, null, null, null), "Output", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel3.setBounds(10, 429, 816, 200);
		contentPane.add(panel3);
		
		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		scrollPane_1.setFont(new Font("Dialog", Font.PLAIN, 13));
		scrollPane_1.setBounds(10, 23, 796, 167);
		panel3.add(scrollPane_1);
		
		JTextArea txtOutput = new JTextArea();
		txtOutput.setMargin(new Insets(2, 5, 2, 5));
		txtOutput.setLineWrap(true);
		txtOutput.setFont(new Font("Dialog", Font.PLAIN, 16));
		scrollPane_1.setViewportView(txtOutput);
		
		JButton btnMaHoa = new JButton("Mã hóa");
		btnMaHoa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (txtInput.getText().isEmpty()) {
					JOptionPane.showMessageDialog(null, "Input không được để trống", "Lỗi", JOptionPane.ERROR_MESSAGE);
					return;
				}
				if (txtKey.getText().isEmpty()) {
					JOptionPane.showMessageDialog(null, "Key không được để trống", "Lỗi", JOptionPane.ERROR_MESSAGE);
					return;
				}
				int keyLength;
				if (cmbKeyLenght.getSelectedItem().toString().equals("128 bits")) {
					keyLength = 128;
				} else if (cmbKeyLenght.getSelectedItem().toString().equals("192 bits")) {
					keyLength = 192;
				} else {
					keyLength = 256;
				}
				txtOutput.setText(Controler.encrypt(txtInput.getText(), txtKey.getText(), keyLength));
			}
		});
		btnMaHoa.setFont(new Font("Dialog", Font.PLAIN, 16));
		btnMaHoa.setBounds(291, 392, 114, 27);
		contentPane.add(btnMaHoa);
		
		JButton btnGiaiMa = new JButton("Giải mã");
		btnGiaiMa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (txtInput.getText().isEmpty()) {
					JOptionPane.showMessageDialog(null, "Input không được để trống", "Lỗi", JOptionPane.ERROR_MESSAGE);
					return;
				}
				if (txtKey.getText().isEmpty()) {
					JOptionPane.showMessageDialog(null, "Key không được để trống", "Lỗi", JOptionPane.ERROR_MESSAGE);
					return;
				}
				int keyLength;
		        if(cmbKeyLenght.getSelectedItem().toString().equals("128 bits")) {
		        	keyLength = 128;
		        } else if(cmbKeyLenght.getSelectedItem().toString().equals("192 bits")) {
		        	keyLength = 192;
		        } else {
		        	keyLength = 256;
		        }
		    	txtOutput.setText(Controler.decrypt(txtInput.getText(), txtKey.getText(), keyLength));
			}
		});
		btnGiaiMa.setFont(new Font("Dialog", Font.PLAIN, 16));
		btnGiaiMa.setBounds(421, 392, 114, 27);
		contentPane.add(btnGiaiMa);
	}
}
